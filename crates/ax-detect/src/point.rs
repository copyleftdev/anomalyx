//! Statistical point-anomaly detector.
//!
//! Flags individual cells that sit far from their column's center using the
//! **Iglewicz–Hoaglin modified z-score**, `M_i = 0.6745·(x_i − median)/MAD`.
//! MAD is used instead of the mean/σ z-score because it is robust: a few wild
//! values don't inflate the spread and mask each other. When MAD is zero (a
//! near-constant column with a handful of different values) the detector falls
//! back to the classic mean/σ z-score; if σ is also zero the column is truly
//! constant and nothing is flagged.
//!
//! Everything is shift- and scale-invariant and order-independent, which is
//! exactly what the property tests pin down.

use crate::config::DetectConfig;
use crate::{Detector, Report};
use ax_core::det;
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, Column, Finding, RecordSet, Value};

/// Iglewicz–Hoaglin scale constant: `1/Φ⁻¹(0.75)`, makes the modified z-score
/// comparable to a standard z-score for normal data.
const MODZ_K: f64 = 0.6745;

#[derive(Debug, Default, Clone)]
pub struct PointDetector;

impl Detector for PointDetector {
    fn id(&self) -> &'static str {
        "point.modz"
    }

    fn class(&self) -> AnomalyClass {
        AnomalyClass::Point
    }

    fn detect(&self, rs: &RecordSet, cfg: &DetectConfig, out: &mut Report) {
        let mut applicable = 0usize;
        for col in &rs.columns {
            if !col.ty.is_numeric() {
                continue;
            }
            let xs = col.numeric();
            if xs.len() < cfg.point_min_n {
                continue;
            }
            applicable += 1;
            self.scan_column(col, &xs, cfg, out);
        }
        if applicable == 0 {
            out.mark_absent(
                self.id(),
                format!(
                    "no numeric column with at least {} finite values",
                    cfg.point_min_n
                ),
            );
        }
    }
}

impl PointDetector {
    fn scan_column(&self, col: &Column, xs: &[f64], cfg: &DetectConfig, out: &mut Report) {
        let Some(center) = det::median(xs) else {
            return;
        };
        let mad = det::mad(xs).unwrap_or(0.0);

        // Choose a robust scale; fall back to σ when MAD collapses.
        let (scale, k) = if mad > 0.0 {
            (mad, MODZ_K)
        } else {
            match det::std_dev(xs) {
                Some(sd) if sd > 0.0 => (sd, 1.0),
                // Constant column: no point can deviate. Honest non-finding.
                _ => return,
            }
        };

        // Iterate the original cells so row indices in handles are correct.
        for (row, cell) in col.cells.iter().enumerate() {
            let Some(x) = numeric_cell(cell) else {
                continue;
            };
            let modz = modified_score(x, center, scale, k);
            if modz <= cfg.point_threshold {
                continue;
            }
            let confidence = confidence_from_modz(modz, cfg.point_threshold);
            let reason = format!(
                "{} = {:.6}: modified z-score {:.3} exceeds {:.3} (center={:.6}, scale={:.6})",
                col.name, x, modz, cfg.point_threshold, center, scale
            );
            out.push(
                Finding::new(
                    self.id(),
                    AnomalyClass::Point,
                    Handle::Cell {
                        column: col.name.clone(),
                        row,
                    },
                    confidence,
                    modz,
                    reason,
                )
                .with_col_type(col.ty),
            );
        }
    }
}

/// Finite numeric projection of a single cell (mirrors [`Value::as_f64`] but
/// drops non-finite values so they never become findings).
fn numeric_cell(v: &Value) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite())
}

/// The (absolute) standardized deviation of `x` from `center` at the given
/// `scale`, multiplied by the consistency constant `k`. Extracted so the exact
/// arithmetic can be pinned by tests, not just its sign.
fn modified_score(x: f64, center: f64, scale: f64, k: f64) -> f64 {
    (k * (x - center) / scale).abs()
}

/// Maps a modified z-score to a calibrated confidence in `[0, 1]`.
///
/// Logistic in the *excess* deviation `modz − threshold`: at the threshold the
/// confidence is 0.5 and it rises monotonically toward 1.0. Strictly increasing
/// in `modz`, which the property tests rely on.
fn confidence_from_modz(modz: f64, threshold: f64) -> f64 {
    let excess = modz - threshold;
    1.0 / (1.0 + (-excess).exp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn col(name: &str, xs: &[f64]) -> Column {
        Column::new(name, xs.iter().map(|&x| Value::Float(x)).collect())
    }

    fn run(xs: &[f64]) -> Report {
        let rs = RecordSet::new("-", "test", vec![col("x", xs)]);
        let mut out = Report::new();
        PointDetector.detect(&rs, &DetectConfig::default(), &mut out);
        out
    }

    /// The set of cell values flagged, for invariance comparisons.
    fn flagged_values(xs: &[f64]) -> Vec<u64> {
        let report = run(xs);
        let mut v: Vec<u64> = report
            .findings
            .iter()
            .map(|f| match &f.handle {
                Handle::Cell { row, .. } => xs[*row].to_bits(),
                _ => unreachable!("point detector emits cell handles"),
            })
            .collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn obvious_outlier_is_flagged() {
        let mut xs = vec![10.0; 30];
        xs.push(1000.0);
        let report = run(&xs);
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            report.findings[0].handle,
            Handle::Cell { row: 30, .. }
        ));
        assert!(report.findings[0].confidence > 0.5);
    }

    #[test]
    fn constant_column_has_no_findings() {
        let report = run(&[7.0; 20]);
        assert!(report.is_clean());
        // It ran (numeric, enough values), so it is NOT marked absent.
        assert!(report.absent.is_empty());
    }

    #[test]
    fn non_numeric_corpus_marks_absent() {
        let rs = RecordSet::new(
            "-",
            "test",
            vec![Column::new(
                "name",
                (0..20).map(|i| Value::Str(format!("u{i}"))).collect(),
            )],
        );
        let mut out = Report::new();
        PointDetector.detect(&rs, &DetectConfig::default(), &mut out);
        assert!(out.is_clean());
        assert_eq!(out.absent.len(), 1);
        assert_eq!(out.absent[0].detector, "point.modz");
    }

    #[test]
    fn too_few_values_marks_absent() {
        let report = run(&[1.0, 2.0, 100.0]); // below default min_n = 8
        assert!(report.is_clean());
        assert_eq!(report.absent.len(), 1);
    }

    #[test]
    fn modified_score_exact_arithmetic() {
        // Pins the formula |k·(x−center)/scale|, not just its sign. Catches any
        // swap of the * , - , or / operators.
        assert_eq!(modified_score(20.0, 10.0, 2.0, 0.5), 2.5);
        assert_eq!(modified_score(0.0, 10.0, 2.0, 1.0), 5.0);
        // negative deviation still yields a positive score
        assert_eq!(modified_score(4.0, 10.0, 3.0, 1.0), 2.0);
    }

    #[test]
    fn confidence_is_half_at_threshold() {
        // excess == 0 ⇒ sigmoid(0) == 0.5 exactly. Catches `modz + threshold`
        // and `modz / threshold` mutations, which both move this off 0.5.
        assert_eq!(confidence_from_modz(3.5, 3.5), 0.5);
        assert_eq!(confidence_from_modz(2.0, 2.0), 0.5);
    }

    #[test]
    fn exactly_min_n_values_is_assessed() {
        // A column with exactly point_min_n (=8) finite values must be scanned,
        // not skipped. Catches `len < min_n` → `len <= min_n`.
        let report = run(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 100.0]);
        assert_eq!(
            report.findings.len(),
            1,
            "the 100.0 outlier must be flagged"
        );
        assert!(report.absent.is_empty(), "8 values is enough to assess");
    }

    #[test]
    fn robust_path_catches_what_sigma_path_misses() {
        // With MAD, the lone 1000 is wildly anomalous. If the detector were
        // forced down the mean/σ fallback, σ is so inflated by that same point
        // that its z-score (~2.7) falls under threshold and nothing is flagged.
        // So this asserts the robust (MAD) branch is actually taken.
        let report = run(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1000.0]);
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            report.findings[0].handle,
            Handle::Cell { row: 8, .. }
        ));
        assert!(
            report.findings[0].score > 100.0,
            "MAD-scaled score is large"
        );
    }

    #[test]
    fn confidence_is_strictly_monotonic() {
        let c1 = confidence_from_modz(4.0, 3.5);
        let c2 = confidence_from_modz(6.0, 3.5);
        let c3 = confidence_from_modz(20.0, 3.5);
        assert!(c1 < c2 && c2 < c3);
        assert!((0.0..=1.0).contains(&c1));
        assert!(c3 <= 1.0);
    }

    proptest! {
        // A clean Gaussian-ish base with one injected spike: the flagged set is
        // invariant to shifting all values by a constant.
        #[test]
        fn shift_invariant(shift in -1e6f64..1e6, base in 1.0f64..5.0) {
            let mut xs: Vec<f64> = (0..40).map(|i| base + (i % 5) as f64 * 0.01).collect();
            xs.push(base + 500.0); // outlier
            let original = flagged_values(&xs);
            let shifted: Vec<f64> = xs.iter().map(|x| x + shift).collect();
            // compare by index, not bits (values differ): recompute against shifted
            let report = run(&shifted);
            let mut rows: Vec<usize> = report.findings.iter().map(|f| match &f.handle {
                Handle::Cell { row, .. } => *row,
                _ => unreachable!(),
            }).collect();
            rows.sort_unstable();
            let mut orig_rows: Vec<usize> = run(&xs).findings.iter().map(|f| match &f.handle {
                Handle::Cell { row, .. } => *row,
                _ => unreachable!(),
            }).collect();
            orig_rows.sort_unstable();
            prop_assert_eq!(rows, orig_rows);
            let _ = original;
        }

        // Scaling by a positive constant does not change which rows are flagged
        // (modified z-score is scale-invariant).
        #[test]
        fn scale_invariant(scale in 0.001f64..1000.0) {
            let mut xs: Vec<f64> = (0..40).map(|i| 100.0 + (i % 7) as f64).collect();
            xs.push(100_000.0); // outlier
            let base_rows = flagged_rows(&xs);
            let scaled: Vec<f64> = xs.iter().map(|x| x * scale).collect();
            prop_assert_eq!(flagged_rows(&scaled), base_rows);
        }

        // Running the same input twice yields byte-identical findings.
        #[test]
        fn deterministic(seed in 0u64..1000) {
            let xs: Vec<f64> = (0..50).map(|i| ((i as u64).wrapping_mul(seed) % 97) as f64).collect();
            let a = run(&xs);
            let b = run(&xs);
            prop_assert_eq!(
                serde_json::to_string(&a.findings).unwrap(),
                serde_json::to_string(&b.findings).unwrap()
            );
        }

        // Row order does not change the multiset of flagged values.
        #[test]
        fn permutation_invariant_values(rot in 1usize..39) {
            let mut xs: Vec<f64> = (0..40).map(|i| 50.0 + (i % 3) as f64).collect();
            xs.push(9999.0);
            let base = flagged_values(&xs);
            xs.rotate_left(rot);
            prop_assert_eq!(flagged_values(&xs), base);
        }
    }

    fn flagged_rows(xs: &[f64]) -> Vec<usize> {
        let mut rows: Vec<usize> = run(xs)
            .findings
            .iter()
            .map(|f| match &f.handle {
                Handle::Cell { row, .. } => *row,
                _ => unreachable!(),
            })
            .collect();
        rows.sort_unstable();
        rows
    }
}
