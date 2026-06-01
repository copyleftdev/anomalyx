//! Multivariate outlier detector (Mahalanobis distance).
//!
//! A point can sit comfortably inside every column's own distribution yet be a
//! glaring outlier *jointly* — e.g. it breaks the correlation the rest of the
//! data obeys. The Mahalanobis distance measures exactly that: distance from the
//! centroid in units that account for each feature's spread and the covariance
//! between features.
//!
//! For data that is roughly multivariate-normal, the squared Mahalanobis
//! distance follows a χ² distribution with `d` degrees of freedom, so the same
//! `statrs` χ² used by the chi-square drift detector gives a principled
//! per-row p-value. Everything is **fully deterministic** — there is no RNG to
//! seed — which is what lets it meet the byte-reproducibility gate that an
//! isolation forest would fight.

use crate::config::DetectConfig;
use crate::dist::chi2_pvalue;
use crate::{calibrate, linalg, Detector, Report, ScanContext};
use ax_core::finding::Handle;
use ax_core::{det, AnomalyClass, Finding, RecordSet};

#[derive(Debug, Default, Clone)]
pub struct MahalanobisDetector;

/// The complete-row feature matrix and the original row index of each row.
struct Features {
    /// `matrix[i]` is the feature vector of the i-th complete row.
    matrix: Vec<Vec<f64>>,
    /// Original corpus row index of each complete row.
    rows: Vec<usize>,
    /// Number of numeric feature columns (`d`).
    dim: usize,
}

impl MahalanobisDetector {
    /// Extracts the numeric feature matrix, keeping only rows where every
    /// numeric column has a finite value (a partial row has no position in
    /// feature space — honest absence, not imputation).
    fn extract(current: &RecordSet, column_roles: bool) -> Option<Features> {
        // Build the feature space from numeric *measurement* columns: an
        // identifier or monotonic-sequence column is a meaningless Mahalanobis
        // dimension (and inflates the covariance with label noise).
        let feats: Vec<&Vec<ax_core::Value>> = current
            .columns
            .iter()
            .filter(|c| c.ty.is_numeric() && !(column_roles && c.role().skips_value_detection()))
            .map(|c| &c.cells)
            .collect();
        let dim = feats.len();
        if dim < 2 {
            return None;
        }
        let mut matrix = Vec::new();
        let mut rows = Vec::new();
        for r in 0..current.rows() {
            let mut row = Vec::with_capacity(dim);
            let complete = feats.iter().all(|cells| match cells[r].as_f64() {
                Some(v) if v.is_finite() => {
                    row.push(v);
                    true
                }
                _ => false,
            });
            if complete {
                matrix.push(row);
                rows.push(r);
            }
        }
        Some(Features { matrix, rows, dim })
    }

    /// Mean vector over the feature matrix.
    fn mean(f: &Features) -> Vec<f64> {
        (0..f.dim)
            .map(|j| {
                let col: Vec<f64> = f.matrix.iter().map(|row| row[j]).collect();
                det::mean(&col).unwrap_or(0.0)
            })
            .collect()
    }

    /// Sample covariance matrix (denominator `n − 1`), with a relative ridge
    /// added to the diagonal for numerical stability.
    fn covariance(f: &Features, mean: &[f64], ridge: f64) -> Vec<Vec<f64>> {
        let n = f.matrix.len();
        let d = f.dim;
        // Center once. Doing the subtraction in a single place matters: because
        // Σ(deviations) == 0, flipping a sign inside a per-term `(x-μ)(y-μ)`
        // would be an equivalent mutant; centering up front ties the sign to the
        // (killable) diagonal variance instead.
        let centered: Vec<Vec<f64>> = f
            .matrix
            .iter()
            .map(|row| (0..d).map(|j| row[j] - mean[j]).collect())
            .collect();
        let mut cov = vec![vec![0.0_f64; d]; d];
        for j in 0..d {
            for k in j..d {
                let prods: Vec<f64> = centered.iter().map(|c| c[j] * c[k]).collect();
                let c = det::det_sum(&prods) / (n - 1) as f64;
                cov[j][k] = c;
                cov[k][j] = c;
            }
        }
        let trace: f64 = det::det_sum(&(0..d).map(|j| cov[j][j]).collect::<Vec<_>>());
        let eps = ridge * (trace / d as f64);
        for (j, row) in cov.iter_mut().enumerate() {
            row[j] += eps;
        }
        cov
    }
}

impl Detector for MahalanobisDetector {
    fn id(&self) -> &'static str {
        "mv.mahalanobis"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Multivariate
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let Some(f) = Self::extract(ctx.current, cfg.column_roles) else {
            out.mark_absent(
                self.id(),
                "needs at least 2 numeric columns for a multivariate distance",
            );
            return;
        };
        if f.matrix.len() < cfg.mv_min_n {
            out.mark_absent(
                self.id(),
                format!(
                    "fewer than {} complete numeric rows to estimate a covariance",
                    cfg.mv_min_n
                ),
            );
            return;
        }

        let mean = Self::mean(&f);
        let cov = Self::covariance(&f, &mean, cfg.mv_ridge);
        let Some(chol) = linalg::cholesky(&cov) else {
            out.mark_absent(
                self.id(),
                "covariance is singular (constant or collinear columns)",
            );
            return;
        };

        for (i, &row) in f.rows.iter().enumerate() {
            let dvec: Vec<f64> = (0..f.dim).map(|j| f.matrix[i][j] - mean[j]).collect();
            let dsq = linalg::mahalanobis_sq(&chol, &dvec);
            let p = chi2_pvalue(dsq, f.dim);
            if p < cfg.mv_alpha {
                out.push(Finding::new(
                    self.id(),
                    AnomalyClass::Multivariate,
                    Handle::Row { row },
                    calibrate::from_undercut(p, cfg.mv_alpha),
                    dsq,
                    format!(
                        "row {row}: Mahalanobis D²={dsq:.3} over {} numeric columns, p={p:.3e} < α={:.3e} — joint outlier",
                        f.dim, cfg.mv_alpha
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{Column, Value};
    use proptest::prelude::*;

    /// Builds a two-column numeric corpus from paired samples.
    fn corpus(xs: &[f64], ys: &[f64]) -> RecordSet {
        RecordSet::new(
            "-",
            "t",
            vec![
                Column::new("x", xs.iter().map(|&v| Value::Float(v)).collect()),
                Column::new("y", ys.iter().map(|&v| Value::Float(v)).collect()),
            ],
        )
    }

    fn run(rs: &RecordSet) -> Report {
        let mut out = Report::new();
        MahalanobisDetector.detect(&ScanContext::single(rs), &DetectConfig::default(), &mut out);
        out
    }

    #[test]
    fn identifier_column_excluded_from_features() {
        // One measurement + one identifier column. With roles on, the identifier
        // is not a feature, leaving a single dimension → mv can't run (needs ≥2).
        // With roles off, both columns are features and it runs.
        let (xs, ys) = correlated(40);
        let rs = RecordSet::new(
            "-",
            "t",
            vec![
                Column::new("x", xs.iter().map(|&v| Value::Float(v)).collect()),
                Column::new("user_id", ys.iter().map(|&v| Value::Float(v)).collect()),
            ],
        );
        let mut on = Report::new();
        MahalanobisDetector.detect(&ScanContext::single(&rs), &DetectConfig::default(), &mut on);
        assert!(
            on.absent.iter().any(|a| a.reason.contains("2 numeric")),
            "identifier excluded ⇒ <2 features ⇒ absent, got {:?}",
            on.absent
        );
        let mut off = Report::new();
        MahalanobisDetector.detect(
            &ScanContext::single(&rs),
            &DetectConfig {
                column_roles: false,
                ..DetectConfig::default()
            },
            &mut off,
        );
        assert!(
            !off.absent.iter().any(|a| a.reason.contains("2 numeric")),
            "both columns are features when roles are off"
        );
    }

    /// A correlated cloud y ≈ x (with small wobble) of `n` points.
    fn correlated(n: usize) -> (Vec<f64>, Vec<f64>) {
        let xs: Vec<f64> = (0..n).map(|i| (i % 10) as f64).collect();
        let ys: Vec<f64> = (0..n)
            .map(|i| (i % 10) as f64 + ((i / 10) % 2) as f64 * 0.4)
            .collect();
        (xs, ys)
    }

    #[test]
    fn needs_two_numeric_columns() {
        let rs = RecordSet::new(
            "-",
            "t",
            vec![Column::new("x", (0..30).map(Value::Int).collect())],
        );
        let report = run(&rs);
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
        assert_eq!(report.absent[0].detector, "mv.mahalanobis");
    }

    #[test]
    fn too_few_complete_rows_is_absent() {
        let (xs, ys) = correlated(10); // below mv_min_n = 20
        let report = run(&corpus(&xs, &ys));
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
    }

    #[test]
    fn constant_columns_are_absent_singular() {
        let xs = vec![5.0; 30];
        let ys = vec![7.0; 30];
        let report = run(&corpus(&xs, &ys));
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
        assert!(report.absent[0].reason.contains("singular"));
    }

    #[test]
    fn clean_correlated_cloud_has_no_findings() {
        let (xs, ys) = correlated(40);
        let report = run(&corpus(&xs, &ys));
        assert!(
            report.findings.is_empty(),
            "no joint outliers in a tidy cloud"
        );
        assert!(
            report.absent.is_empty(),
            "the detector ran; it is not absent"
        );
    }

    #[test]
    fn joint_outlier_is_flagged_though_each_axis_is_in_range() {
        let (mut xs, mut ys) = correlated(40);
        // (0, 9): x and y are each within their normal [0,9] range, but the
        // combination violates the y≈x correlation → large Mahalanobis distance.
        xs.push(0.0);
        ys.push(9.0);
        let report = run(&corpus(&xs, &ys));
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(report.findings[0].handle, Handle::Row { row: 40 }));
        assert_eq!(report.findings[0].class, AnomalyClass::Multivariate);
        // A clear joint outlier sits far past the alpha bar, so the unified
        // undercut calibration drives confidence to the critical end.
        assert!(report.findings[0].confidence > 0.95);
    }

    #[test]
    fn covariance_is_exact() {
        // matrix rows (x,y); means (3,3); var_x=7, var_y=4, cov_xy=5.
        let f = Features {
            matrix: vec![vec![1.0, 1.0], vec![2.0, 3.0], vec![6.0, 5.0]],
            rows: vec![0, 1, 2],
            dim: 2,
        };
        let mean = MahalanobisDetector::mean(&f);
        assert_eq!(mean, vec![3.0, 3.0]);
        let cov = MahalanobisDetector::covariance(&f, &mean, 0.0);
        assert!((cov[0][0] - 7.0).abs() < 1e-12, "var_x");
        assert!((cov[1][1] - 4.0).abs() < 1e-12, "var_y");
        assert!((cov[0][1] - 5.0).abs() < 1e-12, "cov_xy");
        assert_eq!(cov[0][1], cov[1][0], "symmetric");
    }

    #[test]
    fn covariance_ridge_adds_scaled_diagonal() {
        // base diag (7,4); trace=11, d=2, trace/d=5.5; ridge=1.0 ⇒ +5.5 each.
        let f = Features {
            matrix: vec![vec![1.0, 1.0], vec![2.0, 3.0], vec![6.0, 5.0]],
            rows: vec![0, 1, 2],
            dim: 2,
        };
        let mean = MahalanobisDetector::mean(&f);
        let cov = MahalanobisDetector::covariance(&f, &mean, 1.0);
        assert!((cov[0][0] - 12.5).abs() < 1e-12);
        assert!((cov[1][1] - 9.5).abs() < 1e-12);
        // off-diagonal is untouched by the ridge
        assert!((cov[0][1] - 5.0).abs() < 1e-12);
    }

    #[test]
    fn runs_at_exactly_min_n_complete_rows() {
        let n = DetectConfig::default().mv_min_n; // 20
        let (xs, ys) = correlated(n);
        let report = run(&corpus(&xs, &ys));
        assert!(
            report.absent.is_empty(),
            "exactly min_n rows must be assessed"
        );
    }

    #[test]
    fn rows_with_non_finite_values_are_excluded() {
        // 20 rows total but one y is NaN, leaving 19 complete (< min_n = 20),
        // so the detector must report absence rather than counting the NaN row.
        let (xs, mut ys) = correlated(20);
        ys[0] = f64::NAN;
        let report = run(&corpus(&xs, &ys));
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1, "incomplete row must not be counted");
        assert!(report.absent[0].reason.contains("complete"));
    }

    #[test]
    fn deterministic_across_runs() {
        let (mut xs, mut ys) = correlated(40);
        xs.push(0.0);
        ys.push(9.0);
        let rs = corpus(&xs, &ys);
        let a = run(&rs);
        let b = run(&rs);
        assert_eq!(
            serde_json::to_string(&a.findings).unwrap(),
            serde_json::to_string(&b.findings).unwrap()
        );
    }

    proptest! {
        // Mahalanobis distance is translation-invariant: shifting every row by
        // the same vector leaves the flagged rows unchanged (the mean shifts
        // with the data).
        #[test]
        fn translation_invariant(dx in -1e4f64..1e4, dy in -1e4f64..1e4) {
            let (mut xs, mut ys) = correlated(40);
            xs.push(0.0);
            ys.push(9.0);
            let base: Vec<usize> = run(&corpus(&xs, &ys))
                .findings
                .iter()
                .map(|f| match f.handle { Handle::Row { row } => row, _ => unreachable!() })
                .collect();
            let sx: Vec<f64> = xs.iter().map(|v| v + dx).collect();
            let sy: Vec<f64> = ys.iter().map(|v| v + dy).collect();
            let shifted: Vec<usize> = run(&corpus(&sx, &sy))
                .findings
                .iter()
                .map(|f| match f.handle { Handle::Row { row } => row, _ => unreachable!() })
                .collect();
            prop_assert_eq!(base, shifted);
        }
    }
}
