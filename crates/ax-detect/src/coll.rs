//! Collective anomaly detector (CUSUM level shift).
//!
//! A collective anomaly is a *subsequence* that is jointly anomalous even when
//! no single point is — the classic case being a sustained shift in level. On
//! an ordered numeric column (rows = time order) this detector finds the change
//! point that maximizes the cumulative deviation from the global mean (CUSUM),
//! measures the standardized difference between the two segments, and — when
//! that shift is large — flags the post-change segment as a [`Handle::Range`].
//!
//! Fully deterministic: means via order-independent reductions, and the change
//! point chosen by a stable arg-max (first maximal split wins).

use crate::config::DetectConfig;
use crate::{calibrate, Detector, Report, ScanContext};
use ax_core::det;
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, Finding};

#[derive(Debug, Default, Clone)]
pub struct CusumDetector;

/// Index `m` (a split into `[0, m)` and `[m, n)`) that maximizes `|CUSUM|` over
/// interior split points. Returns `0` if there is no interior split.
pub fn cusum_changepoint(xs: &[f64], mean: f64) -> usize {
    let n = xs.len();
    let mut s = 0.0_f64;
    let mut best = -1.0_f64;
    let mut m = 0;
    for (k, &x) in xs.iter().enumerate() {
        s += x - mean;
        let split = k + 1;
        if split < n && s.abs() > best {
            best = s.abs();
            m = split;
        }
    }
    m
}

/// Standardized two-segment mean difference
/// `|meanL − meanR| / (σ·√(1/nl + 1/nr))`. Extracted so the exact arithmetic is
/// pinned by tests.
pub fn standardized_shift(mean_l: f64, mean_r: f64, sigma: f64, nl: usize, nr: usize) -> f64 {
    let se = sigma * (1.0 / nl as f64 + 1.0 / nr as f64).sqrt();
    (mean_l - mean_r).abs() / se
}

impl Detector for CusumDetector {
    fn id(&self) -> &'static str {
        "coll.cusum"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Collective
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let mut applicable = false;
        for col in &ctx.current.columns {
            if !col.ty.is_numeric() {
                continue;
            }
            // Skip identifier/sequence columns: a "level shift" in arbitrary ids
            // is meaningless, and a monotonic counter is one big ramp the CUSUM
            // would always flag. (`column_roles = false` disables this.)
            if cfg.column_roles && col.role().skips_value_detection() {
                continue;
            }
            // Finite values in row order, with their original row indices.
            let pairs: Vec<(usize, f64)> = col
                .cells
                .iter()
                .enumerate()
                .filter_map(|(row, cell)| cell.as_f64().filter(|v| v.is_finite()).map(|v| (row, v)))
                .collect();
            if pairs.len() < cfg.coll_min_n {
                continue;
            }
            let xs: Vec<f64> = pairs.iter().map(|(_, v)| *v).collect();
            let n = xs.len();
            let mean = det::mean(&xs).unwrap_or(0.0);
            let sigma = match det::std_dev(&xs) {
                Some(s) if s > 0.0 => s,
                _ => continue, // constant column: no shift possible
            };
            applicable = true;

            let m = cusum_changepoint(&xs, mean);
            if m == 0 {
                continue;
            }
            let mean_l = det::mean(&xs[..m]).unwrap_or(0.0);
            let mean_r = det::mean(&xs[m..]).unwrap_or(0.0);
            let shift = standardized_shift(mean_l, mean_r, sigma, m, n - m);
            if shift > cfg.coll_threshold {
                let start = pairs[m].0;
                let end = pairs[n - 1].0 + 1;
                out.push(Finding::new(
                    self.id(),
                    AnomalyClass::Collective,
                    Handle::Range {
                        column: col.name.clone(),
                        start,
                        end,
                    },
                    calibrate::from_exceedance(shift, cfg.coll_threshold),
                    shift,
                    format!(
                        "{}: level shift at row {start} — mean {mean_l:.4} → {mean_r:.4}, standardized shift {shift:.3} > {:.3}",
                        col.name, cfg.coll_threshold
                    ),
                ));
            }
        }
        if !applicable {
            out.mark_absent(
                self.id(),
                format!(
                    "no numeric column with ≥ {} values and non-zero variance",
                    cfg.coll_min_n
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{Column, RecordSet, Value};

    fn corpus(values: &[f64]) -> RecordSet {
        RecordSet::new(
            "-",
            "t",
            vec![Column::new(
                "v",
                values.iter().map(|&x| Value::Float(x)).collect(),
            )],
        )
    }

    fn run(rs: &RecordSet) -> Report {
        let mut out = Report::new();
        CusumDetector.detect(&ScanContext::single(rs), &DetectConfig::default(), &mut out);
        out
    }

    #[test]
    fn changepoint_finds_the_shift_index() {
        let xs = [0.0, 0.0, 0.0, 10.0, 10.0, 10.0];
        let mean = det::mean(&xs).unwrap();
        assert_eq!(cusum_changepoint(&xs, mean), 3);
    }

    #[test]
    fn changepoint_on_flat_series_is_first_interior_split() {
        // With no movement every |CUSUM| is 0; the running best must start below
        // 0 so the first interior split is selected (pins the `-1.0` seed).
        assert_eq!(cusum_changepoint(&[5.0, 5.0, 5.0, 5.0], 5.0), 1);
    }

    #[test]
    fn changepoint_breaks_ties_to_the_first_peak() {
        // |CUSUM| peaks equally at splits 1, 3, 5; strict `>` keeps the first.
        let xs = [2.0, -2.0, 2.0, -2.0, 2.0, -2.0];
        assert_eq!(cusum_changepoint(&xs, 0.0), 1);
    }

    #[test]
    fn standardized_shift_is_exact() {
        // |0 − 6| / (2·√(1/2 + 1/2)) = 6 / 2 = 3.
        assert!((standardized_shift(0.0, 6.0, 2.0, 2, 2) - 3.0).abs() < 1e-12);
        // asymmetric segment sizes: |0 − 2| / (1·√(1 + 1/3)) = 2/√(4/3) = √3.
        assert!((standardized_shift(0.0, 2.0, 1.0, 1, 3) - 3.0_f64.sqrt()).abs() < 1e-12);
    }

    #[test]
    fn identifier_column_is_skipped_by_role() {
        // A clean 10→40 level shift that a measurement column would flag as a
        // range — but a shift in arbitrary ids is meaningless.
        let mut v: Vec<f64> = vec![10.0; 20];
        v.extend(std::iter::repeat_n(40.0, 20));
        let rs = RecordSet::new(
            "-",
            "t",
            vec![Column::new(
                "user_id",
                v.iter().map(|&x| Value::Float(x)).collect(),
            )],
        );
        let mut on = Report::new();
        CusumDetector.detect(&ScanContext::single(&rs), &DetectConfig::default(), &mut on);
        assert!(
            on.findings.is_empty(),
            "cusum on an identifier column is skipped"
        );
        let mut off = Report::new();
        CusumDetector.detect(
            &ScanContext::single(&rs),
            &DetectConfig {
                column_roles: false,
                ..DetectConfig::default()
            },
            &mut off,
        );
        assert_eq!(off.findings.len(), 1, "--no-column-roles assesses it");
    }

    #[test]
    fn sustained_level_shift_is_flagged_as_a_range() {
        // Clean 10→40 step at row 20 (no noise) so segment means are exactly
        // 10 and 40 and the score can be pinned.
        let mut v: Vec<f64> = vec![10.0; 20];
        v.extend(std::iter::repeat_n(40.0, 20));
        let report = run(&corpus(&v));
        assert_eq!(report.findings.len(), 1);
        match &report.findings[0].handle {
            Handle::Range { start, end, .. } => {
                assert_eq!(*start, 20, "the shift begins at row 20");
                assert_eq!(*end, 40);
            }
            other => panic!("expected a Range handle, got {other:?}"),
        }
        assert_eq!(report.findings[0].class, AnomalyClass::Collective);
        // The reported score is the standardized shift over the correct segment
        // sizes (20 and 20) — pins the `n - m` right-segment count.
        let sigma = det::std_dev(&v).unwrap();
        let expected = standardized_shift(10.0, 40.0, sigma, 20, 20);
        assert!((report.findings[0].score - expected).abs() < 1e-9);
    }

    #[test]
    fn runs_at_exactly_min_n() {
        // Exactly coll_min_n rows must be assessed (not skipped). A balanced
        // 50/50 split of n=20 has a standardized shift of √20 ≈ 4.47 < 5, so it
        // produces no finding — but the column ran, so it is not marked absent.
        let n = DetectConfig::default().coll_min_n; // 20
        let mut v: Vec<f64> = vec![10.0; n / 2];
        v.extend(std::iter::repeat_n(40.0, n / 2));
        let report = run(&corpus(&v));
        assert!(
            report.absent.is_empty(),
            "exactly min_n rows must be assessed"
        );
    }

    #[test]
    fn stationary_series_has_no_findings() {
        let v: Vec<f64> = (0..40).map(|i| 10.0 + (i % 5) as f64 * 0.1).collect();
        let report = run(&corpus(&v));
        assert!(
            report.findings.is_empty(),
            "no shift, no collective anomaly"
        );
        assert!(report.absent.is_empty(), "it ran; not absent");
    }

    #[test]
    fn too_short_is_absent() {
        let report = run(&corpus(&[1.0, 2.0, 3.0]));
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
    }

    #[test]
    fn constant_column_is_absent() {
        let report = run(&corpus(&[7.0; 30]));
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
    }

    #[test]
    fn deterministic_across_runs() {
        let mut v: Vec<f64> = (0..20).map(|_| 10.0).collect();
        v.extend((0..20).map(|_| 40.0));
        let rs = corpus(&v);
        let a = run(&rs);
        let b = run(&rs);
        assert_eq!(
            serde_json::to_string(&a.findings).unwrap(),
            serde_json::to_string(&b.findings).unwrap()
        );
    }
}
