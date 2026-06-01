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
use crate::{calibrate, fdr, robustz, Detector, Report, ScanContext};
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, Column, Finding, Role, Value};

#[derive(Debug, Default, Clone)]
pub struct PointDetector;

impl Detector for PointDetector {
    fn id(&self) -> &'static str {
        "point.modz"
    }

    fn class(&self) -> AnomalyClass {
        AnomalyClass::Point
    }

    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let mut eligible = 0usize; // numeric columns with enough finite values
        let mut scanned = 0usize; // of those, the ones a role didn't skip
        for col in &ctx.current.columns {
            if !col.ty.is_numeric() {
                continue;
            }
            let xs = col.numeric();
            if xs.len() < cfg.point_min_n {
                continue;
            }
            eligible += 1;
            // Skip columns whose role makes a magnitude outlier meaningless: an
            // identifier (arbitrary label) or a monotonic sequence (a ramp's
            // "outlier" is just its endpoint). A constant column is left to
            // `scan_column` (it self-no-ops). Roles still ship in the envelope;
            // `column_roles = false` disables this skipping entirely.
            if cfg.column_roles && matches!(col.role(), Role::Identifier | Role::Sequence) {
                continue;
            }
            scanned += 1;
            self.scan_column(col, &xs, cfg, out);
        }
        // Honest absence only when there was nothing to measure in the first
        // place — not when columns existed but were all role-skipped (point ran;
        // it simply had no measurement column to flag).
        if eligible == 0 {
            out.mark_absent(
                self.id(),
                format!(
                    "no numeric column with at least {} finite values",
                    cfg.point_min_n
                ),
            );
        } else if scanned == 0 {
            out.mark_absent(
                self.id(),
                "every numeric column was an identifier, category, or sequence \
                 (no measurement column to assess; see `roles`)"
                    .to_string(),
            );
        }
    }
}

impl PointDetector {
    fn scan_column(&self, col: &Column, xs: &[f64], cfg: &DetectConfig, out: &mut Report) {
        // Robust center/scale; a constant column has none and flags nothing.
        let Some((center, scale, k)) = robustz::center_scale(xs) else {
            return;
        };

        match cfg.point_fdr_q {
            Some(q) => self.scan_column_fdr(col, center, scale, q, out),
            None => self.scan_column_threshold(col, center, scale, k, cfg, out),
        }
    }

    /// Fixed-cutoff mode: flag every cell whose modified z-score exceeds
    /// `point_threshold`. No multiplicity control.
    fn scan_column_threshold(
        &self,
        col: &Column,
        center: f64,
        scale: f64,
        k: f64,
        cfg: &DetectConfig,
        out: &mut Report,
    ) {
        // Iterate the original cells so row indices in handles are correct.
        for (row, cell) in col.cells.iter().enumerate() {
            let Some(x) = numeric_cell(cell) else {
                continue;
            };
            let modz = robustz::score(x, center, scale, k);
            if modz <= cfg.point_threshold {
                continue;
            }
            let reason = format!(
                "{} = {:.6}: modified z-score {:.3} exceeds {:.3} (center={:.6}, scale={:.6})",
                col.name, x, modz, cfg.point_threshold, center, scale
            );
            self.emit(
                col,
                row,
                modz,
                calibrate::from_exceedance(modz, cfg.point_threshold),
                reason,
                out,
            );
        }
    }

    /// FDR mode: convert each cell's modified z-score to a two-sided p-value and
    /// flag only the cells that survive Benjamini–Hochberg control at level `q`
    /// *within this column*. A column that is really just noise rejects nothing,
    /// so it stops contributing chance flags; the fixed threshold is bypassed.
    fn scan_column_fdr(&self, col: &Column, center: f64, scale: f64, q: f64, out: &mut Report) {
        // First pass: (row, value, |z|, p) for every finite cell, in cell order.
        // `z = (x − center)/scale` is the consistent-σ standardized deviation
        // (≈ N(0, 1) under the null in both the MAD and σ branches) — unlike
        // `robustz::score`, which additionally folds in the display constant
        // `MODZ_K`, so it is not on a unit-variance scale and would mis-state the
        // p-value. We use `z` for the p-value (the FDR decision) and as the
        // reported score.
        let mut cand: Vec<(usize, f64, f64, f64)> = Vec::new();
        for (row, cell) in col.cells.iter().enumerate() {
            let Some(x) = numeric_cell(cell) else {
                continue;
            };
            let z = ((x - center) / scale).abs();
            cand.push((row, x, z, fdr::two_sided_p(z)));
        }

        let pvals: Vec<f64> = cand.iter().map(|c| c.3).collect();
        let Some(cutoff) = fdr::benjamini_hochberg(&pvals, q) else {
            return; // nothing significant in this column
        };

        // Second pass: emit the cells BH rejects (p ≤ cutoff), in row order.
        for (row, x, z, p) in cand {
            if p > cutoff {
                continue;
            }
            let reason = format!(
                "{} = {:.6}: standardized deviation z={:.3}, p={:.3e} ≤ BH cutoff \
                 {:.3e} at FDR q={:.4} (center={:.6}, scale={:.6})",
                col.name, x, z, p, cutoff, q, center, scale
            );
            self.emit(
                col,
                row,
                z,
                calibrate::from_undercut(p, cutoff),
                reason,
                out,
            );
        }
    }

    /// Pushes a point finding for cell `row` with the given `score` (the
    /// magnitude statistic) and calibrated `confidence` in `[0, 1]`.
    fn emit(
        &self,
        col: &Column,
        row: usize,
        score: f64,
        confidence: f64,
        reason: String,
        out: &mut Report,
    ) {
        out.push(
            Finding::new(
                self.id(),
                AnomalyClass::Point,
                Handle::Cell {
                    column: col.name.clone(),
                    row,
                },
                confidence,
                score,
                reason,
            )
            .with_col_type(col.ty),
        );
    }
}

/// Finite numeric projection of a single cell (mirrors [`Value::as_f64`] but
/// drops non-finite values so they never become findings).
fn numeric_cell(v: &Value) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn col(name: &str, xs: &[f64]) -> Column {
        Column::new(name, xs.iter().map(|&x| Value::Float(x)).collect())
    }

    fn run(xs: &[f64]) -> Report {
        let rs = ax_core::RecordSet::new("-", "test", vec![col("x", xs)]);
        let mut out = Report::new();
        PointDetector.detect(
            &ScanContext::single(&rs),
            &DetectConfig::default(),
            &mut out,
        );
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

    fn run_cfg(xs: &[f64], cfg: &DetectConfig) -> Report {
        let rs = ax_core::RecordSet::new("-", "test", vec![col("x", xs)]);
        let mut out = Report::new();
        PointDetector.detect(&ScanContext::single(&rs), cfg, &mut out);
        out
    }

    fn fdr_cfg(q: f64) -> DetectConfig {
        DetectConfig {
            point_fdr_q: Some(q),
            ..DetectConfig::default()
        }
    }

    #[test]
    fn fdr_flags_the_clear_outlier() {
        // A blatant outlier has p ≈ 0, which Benjamini–Hochberg rejects in any
        // column — FDR mode still catches what matters.
        let mut xs = vec![10.0; 30];
        xs.push(1000.0);
        let r = run_cfg(&xs, &fdr_cfg(0.05));
        assert_eq!(r.findings.len(), 1);
        assert!(matches!(r.findings[0].handle, Handle::Cell { row: 30, .. }));
        // The reason records the FDR decision, not a fixed threshold.
        assert!(r.findings[0].reason.contains("FDR q="));
    }

    #[test]
    fn fdr_adapts_to_the_number_of_tests() {
        // The SAME outlier — standardized deviation z ≈ 4.0 (two-sided p ≈
        // 6.3e-5) over a symmetric [-1, 0, 1] base (median 0, consistent scale
        // 1.4826) — is significant in a small column but not in a large one,
        // because BH's per-rank bar (k/m)·q shrinks with the number of cells
        // tested. That multiplicity awareness is exactly what a fixed cutoff
        // lacks. The base cells (z ≈ 0.45) are never flagged in either column.
        let outlier = 4.0 * 1.4826; // (x − 0)/1.4826 = z ≈ 4.0
        let make = |n: usize| {
            let mut xs = Vec::new();
            for _ in 0..n {
                xs.extend_from_slice(&[-1.0, 0.0, 1.0]);
            }
            xs.push(outlier);
            xs
        };
        let small = run_cfg(&make(7), &fdr_cfg(0.05)); // m = 22:  (1/22)·.05 ≈ 2.3e-3 ≥ p
        let large = run_cfg(&make(700), &fdr_cfg(0.05)); // m = 2101: (1/2101)·.05 ≈ 2.4e-5 < p
        assert_eq!(small.findings.len(), 1, "rare in a small column ⇒ flagged");
        assert_eq!(
            large.findings.len(),
            0,
            "the same cell among 2101 tests ⇒ not significant after correction"
        );
    }

    #[test]
    fn fdr_uses_deviation_from_center_not_sum() {
        // Median 100, a tight base around it, and one real outlier at 200. The
        // standardized deviation is (x − center)/scale: only the 200 is extreme.
        // Were it (x + center) instead, every base cell would look ~130 σ out
        // (98 + 100 ≈ 198) and get flagged — so this pins the subtraction sign.
        let mut xs: Vec<f64> = Vec::new();
        for _ in 0..20 {
            xs.extend_from_slice(&[98.0, 99.0, 100.0, 101.0, 102.0]);
        }
        xs.push(200.0);
        let r = run_cfg(&xs, &fdr_cfg(0.05));
        assert_eq!(r.findings.len(), 1, "only the 200 outlier is significant");
        assert!(matches!(
            r.findings[0].handle,
            Handle::Cell { row: 100, .. }
        ));
    }

    fn cfg_no_roles() -> DetectConfig {
        DetectConfig {
            column_roles: false,
            ..DetectConfig::default()
        }
    }

    #[test]
    fn identifier_named_column_is_skipped_by_role() {
        // An id-named numeric column with a blatant "outlier": skipped when roles
        // are on (a big PID is not an anomaly), scanned when roles are off.
        let mut xs = vec![100.0; 30];
        xs.push(999_999.0);
        let id_col = col("_PID", &xs);
        let rs = ax_core::RecordSet::new("-", "t", vec![id_col]);

        let mut on = Report::new();
        PointDetector.detect(&ScanContext::single(&rs), &DetectConfig::default(), &mut on);
        assert!(
            on.findings.is_empty(),
            "identifier column must be role-skipped"
        );
        // It WAS the only numeric column and it was skipped → honest absence.
        assert_eq!(on.absent.len(), 1);

        let mut off = Report::new();
        PointDetector.detect(&ScanContext::single(&rs), &cfg_no_roles(), &mut off);
        assert_eq!(
            off.findings.len(),
            1,
            "--no-column-roles scans it as before"
        );
    }

    #[test]
    fn measurement_column_alongside_identifier_still_scanned() {
        // A measurement column is assessed even when an identifier column sits
        // next to it; only the identifier is skipped.
        let mut m = vec![10.0; 30];
        m.push(1000.0);
        let rs = ax_core::RecordSet::new("-", "t", vec![col("fare", &m), col("user_id", &m)]);
        let mut out = Report::new();
        PointDetector.detect(
            &ScanContext::single(&rs),
            &DetectConfig::default(),
            &mut out,
        );
        assert_eq!(
            out.findings.len(),
            1,
            "only the measurement column's outlier"
        );
        match &out.findings[0].handle {
            Handle::Cell { column, .. } => assert_eq!(column, "fare"),
            _ => unreachable!(),
        }
        assert!(out.absent.is_empty(), "a measurement column WAS assessed");
    }

    #[test]
    fn fdr_off_matches_the_threshold_path_exactly() {
        // With point_fdr_q = None the FDR machinery is inert: identical findings.
        let xs = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1000.0];
        let off = run_cfg(&xs, &DetectConfig::default());
        assert_eq!(off.findings.len(), 1);
        assert!(off.findings[0].reason.contains("exceeds"));
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
        let rs = ax_core::RecordSet::new(
            "-",
            "test",
            vec![Column::new(
                "name",
                (0..20).map(|i| Value::Str(format!("u{i}"))).collect(),
            )],
        );
        let mut out = Report::new();
        PointDetector.detect(
            &ScanContext::single(&rs),
            &DetectConfig::default(),
            &mut out,
        );
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
