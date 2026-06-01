//! Distributional drift detectors — they compare a column in the *current*
//! corpus against the same column in a *baseline*. With no baseline they report
//! honest [`Absence`](ax_core::envelope::Absence): drift is undefined without
//! something to drift from.
//!
//! - [`KsDetector`] — two-sample Kolmogorov–Smirnov (numeric): is the shape/
//!   location of the distribution different? Reports the D statistic + p-value.
//! - [`PsiDetector`] — Population Stability Index over baseline-quantile bins
//!   (numeric): *how much* mass moved. This is the binned, symmetric cousin of
//!   KL divergence.
//! - [`Chi2Detector`] — chi-square over category frequencies (categorical):
//!   did the category mix change, or did new categories appear?
//!
//! The statistics are deterministic: sorted samples, fixed bin edges derived
//! from baseline quantiles, and order-independent reductions via [`ax_core::det`].

use crate::calibrate;
use crate::config::DetectConfig;
use crate::{Detector, Report, ScanContext};
use ax_core::det;
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, Column, Finding, RecordSet};
use statrs::distribution::{ChiSquared, ContinuousCDF};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Kolmogorov–Smirnov
// ---------------------------------------------------------------------------

/// Two-sample KS statistic D: the maximum gap between the empirical CDFs of
/// `a` and `b`. `None` if either sample is empty. Ties are advanced on both
/// sides simultaneously so the statistic is well-defined for discrete data.
pub fn ks_statistic(a: &[f64], b: &[f64]) -> Option<f64> {
    if a.is_empty() || b.is_empty() {
        return None;
    }
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort_by(f64::total_cmp);
    b.sort_by(f64::total_cmp);
    let (n, m) = (a.len(), b.len());
    let (mut i, mut j) = (0usize, 0usize);
    let mut d = 0.0_f64;
    while i < n && j < m {
        let (av, bv) = (a[i], b[j]);
        if av <= bv {
            let v = av;
            while i < n && a[i] == v {
                i += 1;
            }
        }
        if bv <= av {
            let v = bv;
            while j < m && b[j] == v {
                j += 1;
            }
        }
        let diff = (i as f64 / n as f64) - (j as f64 / m as f64);
        d = d.max(diff.abs());
    }
    Some(d)
}

/// The Kolmogorov distribution survival function
/// `Q(λ) = 2·Σ_{k≥1} (−1)^{k−1} e^{−2k²λ²}`, used to turn a KS statistic into a
/// p-value. `Q(0) = 1`; it decreases monotonically toward 0.
pub fn ks_q(lambda: f64) -> f64 {
    if lambda <= 0.0 {
        return 1.0;
    }
    let mut terms = Vec::with_capacity(100);
    for k in 1..=100i32 {
        let sign = if k % 2 == 1 { 1.0 } else { -1.0 };
        terms.push(sign * (-2.0 * (k as f64).powi(2) * lambda * lambda).exp());
    }
    (2.0 * det::det_sum(&terms)).clamp(0.0, 1.0)
}

/// Asymptotic two-sample KS p-value for statistic `d` with sample sizes `n`, `m`.
pub fn ks_pvalue(d: f64, n: usize, m: usize) -> f64 {
    let en = (n as f64 * m as f64 / (n as f64 + m as f64)).sqrt();
    let lambda = (en + 0.12 + 0.11 / en) * d;
    ks_q(lambda)
}

// ---------------------------------------------------------------------------
// Population Stability Index
// ---------------------------------------------------------------------------

/// Interior bin edges at the `1/bins … (bins−1)/bins` quantiles of `baseline`.
fn quantile_edges(baseline: &[f64], bins: usize) -> Vec<f64> {
    (1..bins)
        .filter_map(|k| det::quantile(baseline, k as f64 / bins as f64))
        .collect()
}

/// Counts of `xs` falling into each of `bins` bins delimited by `edges`.
fn bin_counts(xs: &[f64], edges: &[f64], bins: usize) -> Vec<usize> {
    // `edges` has exactly `bins - 1` entries, so partition_point is already in
    // `0..=bins-1`; no clamp needed (and adding one would be an equivalent mutant).
    let mut counts = vec![0usize; bins];
    for &v in xs {
        let idx = edges.partition_point(|&e| e <= v);
        counts[idx] += 1;
    }
    counts
}

/// Population Stability Index of `current` against `baseline`, using `bins`
/// baseline-quantile bins. `None` if either side is too small to bin.
/// `PSI = Σ (c_i − b_i)·ln(c_i / b_i)` over bin fractions, with a small floor to
/// keep empty bins finite.
pub fn psi(baseline: &[f64], current: &[f64], bins: usize) -> Option<f64> {
    if bins < 2 || baseline.len() < bins || current.is_empty() {
        return None;
    }
    let edges = quantile_edges(baseline, bins);
    let bc = bin_counts(baseline, &edges, bins);
    let cc = bin_counts(current, &edges, bins);
    let (bt, ct) = (baseline.len() as f64, current.len() as f64);
    const FLOOR: f64 = 1e-4;
    let terms: Vec<f64> = (0..bins)
        .map(|k| {
            let b = (bc[k] as f64 / bt).max(FLOOR);
            let c = (cc[k] as f64 / ct).max(FLOOR);
            (c - b) * (c / b).ln()
        })
        .collect();
    Some(det::det_sum(&terms))
}

// ---------------------------------------------------------------------------
// Chi-square over categories
// ---------------------------------------------------------------------------

/// Category → count for the non-null cells of a column.
fn category_counts(col: &Column) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for cell in &col.cells {
        if cell.is_null() {
            continue;
        }
        *counts.entry(cell.canonical()).or_insert(0) += 1;
    }
    counts
}

/// Chi-square statistic and degrees of freedom comparing `current` category
/// counts against the proportions implied by `baseline`. New categories (absent
/// in baseline) contribute strongly via the small expected-count floor.
/// `None` if either side has no observations.
pub fn chi2_categorical(
    baseline: &BTreeMap<String, usize>,
    current: &BTreeMap<String, usize>,
) -> Option<(f64, usize)> {
    let bt: usize = baseline.values().sum();
    let ct: usize = current.values().sum();
    if bt == 0 || ct == 0 {
        return None;
    }
    let cats: std::collections::BTreeSet<&String> = baseline.keys().chain(current.keys()).collect();
    const FLOOR: f64 = 0.5;
    let terms: Vec<f64> = cats
        .iter()
        .map(|cat| {
            let bc = *baseline.get(*cat).unwrap_or(&0) as f64;
            let cc = *current.get(*cat).unwrap_or(&0) as f64;
            let expected = (bc / bt as f64 * ct as f64).max(FLOOR);
            // deviation computed once: `(cc-e)*(cc-e)` would make a single sign
            // flip an equivalent mutant (Σ(cc+e)(cc-e) == Σ(cc-e)² is false here,
            // but per-term cc²-e² can coincide), so bind it.
            let dev = cc - expected;
            dev * dev / expected
        })
        .collect();
    let dof = cats.len().saturating_sub(1).max(1);
    Some((det::det_sum(&terms), dof))
}

/// p-value of a chi-square statistic with `dof` degrees of freedom.
pub fn chi2_pvalue(stat: f64, dof: usize) -> f64 {
    match ChiSquared::new(dof as f64) {
        Ok(dist) => (1.0 - dist.cdf(stat)).clamp(0.0, 1.0),
        Err(_) => 1.0,
    }
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

/// Iterates numeric columns present and numeric in both corpora with at least
/// `min_n` finite values per side, invoking `f(name, baseline_vals, cur_vals)`.
/// Returns whether any column was applicable.
fn for_paired_numeric(
    current: &RecordSet,
    baseline: &RecordSet,
    min_n: usize,
    mut f: impl FnMut(&str, &[f64], &[f64]),
) -> bool {
    let mut any = false;
    for col in &current.columns {
        if !col.ty.is_numeric() {
            continue;
        }
        let Some(bcol) = baseline.column(&col.name) else {
            continue;
        };
        if !bcol.ty.is_numeric() {
            continue;
        }
        let (cur, bas) = (col.numeric(), bcol.numeric());
        if cur.len() < min_n || bas.len() < min_n {
            continue;
        }
        any = true;
        f(&col.name, &bas, &cur);
    }
    any
}

const NO_BASELINE: &str = "no baseline provided; distributional drift requires --baseline";

/// Two-sample KS drift detector.
#[derive(Debug, Default, Clone)]
pub struct KsDetector;

impl Detector for KsDetector {
    fn id(&self) -> &'static str {
        "dist.ks"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Distributional
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let Some(baseline) = ctx.baseline else {
            out.mark_absent(self.id(), NO_BASELINE);
            return;
        };
        let any = for_paired_numeric(ctx.current, baseline, cfg.dist_min_n, |name, bas, cur| {
            let Some(d) = ks_statistic(bas, cur) else {
                return;
            };
            let p = ks_pvalue(d, bas.len(), cur.len());
            if p < cfg.dist_alpha {
                out.push(Finding::new(
                    self.id(),
                    AnomalyClass::Distributional,
                    Handle::Dist {
                        column: name.to_string(),
                    },
                    calibrate::from_undercut(p, cfg.dist_alpha),
                    d,
                    format!(
                        "{name}: KS D={d:.4}, p={p:.4} < α={:.4} — distribution shifted",
                        cfg.dist_alpha
                    ),
                ));
            }
        });
        if !any {
            out.mark_absent(
                self.id(),
                format!(
                    "no numeric column shared by both corpora with ≥ {} values",
                    cfg.dist_min_n
                ),
            );
        }
    }
}

/// PSI drift detector.
#[derive(Debug, Default, Clone)]
pub struct PsiDetector;

impl Detector for PsiDetector {
    fn id(&self) -> &'static str {
        "dist.psi"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Distributional
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let Some(baseline) = ctx.baseline else {
            out.mark_absent(self.id(), NO_BASELINE);
            return;
        };
        let any = for_paired_numeric(ctx.current, baseline, cfg.dist_min_n, |name, bas, cur| {
            let Some(value) = psi(bas, cur, cfg.psi_bins) else {
                return;
            };
            if value > cfg.psi_threshold {
                out.push(Finding::new(
                    self.id(),
                    AnomalyClass::Distributional,
                    Handle::Dist {
                        column: name.to_string(),
                    },
                    calibrate::from_exceedance(value, cfg.psi_threshold),
                    value,
                    format!(
                        "{name}: PSI={value:.4} > {:.4} — population shifted",
                        cfg.psi_threshold
                    ),
                ));
            }
        });
        if !any {
            out.mark_absent(
                self.id(),
                format!(
                    "no numeric column shared by both corpora with ≥ {} values",
                    cfg.dist_min_n
                ),
            );
        }
    }
}

/// Chi-square categorical drift detector.
#[derive(Debug, Default, Clone)]
pub struct Chi2Detector;

impl Detector for Chi2Detector {
    fn id(&self) -> &'static str {
        "dist.chi2"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Distributional
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let Some(baseline) = ctx.baseline else {
            out.mark_absent(self.id(), NO_BASELINE);
            return;
        };
        let mut any = false;
        for col in &ctx.current.columns {
            // Categorical = string/bool columns; numerics are KS/PSI's job.
            if col.ty.is_numeric() {
                continue;
            }
            let Some(bcol) = baseline.column(&col.name) else {
                continue;
            };
            let (bc, cc) = (category_counts(bcol), category_counts(col));
            let Some((stat, dof)) = chi2_categorical(&bc, &cc) else {
                continue;
            };
            any = true;
            let p = chi2_pvalue(stat, dof);
            if p < cfg.dist_alpha {
                out.push(Finding::new(
                    self.id(),
                    AnomalyClass::Distributional,
                    Handle::Dist {
                        column: col.name.clone(),
                    },
                    calibrate::from_undercut(p, cfg.dist_alpha),
                    stat,
                    format!(
                        "{}: χ²={stat:.3} (dof={dof}), p={p:.4} < α={:.4} — category mix changed",
                        col.name, cfg.dist_alpha
                    ),
                ));
            }
        }
        if !any {
            out.mark_absent(self.id(), "no categorical column shared by both corpora");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::Value;
    use proptest::prelude::*;

    fn ncol(name: &str, xs: &[f64]) -> Column {
        Column::new(name, xs.iter().map(|&x| Value::Float(x)).collect())
    }
    fn scol(name: &str, ss: &[&str]) -> Column {
        Column::new(name, ss.iter().map(|s| Value::Str(s.to_string())).collect())
    }

    #[test]
    fn ks_identical_samples_is_zero() {
        let xs: Vec<f64> = (0..50).map(|i| i as f64).collect();
        assert_eq!(ks_statistic(&xs, &xs), Some(0.0));
    }

    #[test]
    fn ks_disjoint_supports_is_one() {
        let a: Vec<f64> = (0..50).map(|i| i as f64).collect();
        let b: Vec<f64> = (100..150).map(|i| i as f64).collect();
        assert_eq!(ks_statistic(&a, &b), Some(1.0));
    }

    #[test]
    fn ks_empty_is_none() {
        assert_eq!(ks_statistic(&[], &[1.0]), None);
        assert_eq!(ks_statistic(&[1.0], &[]), None);
    }

    #[test]
    fn ks_q_bounds_and_monotonic() {
        assert_eq!(ks_q(0.0), 1.0);
        let a = ks_q(0.5);
        let b = ks_q(1.0);
        let c = ks_q(2.0);
        assert!(a > b && b > c);
        assert!((0.0..=1.0).contains(&a));
        assert!(c >= 0.0);
    }

    #[test]
    fn ks_pvalue_small_for_disjoint() {
        let p = ks_pvalue(1.0, 50, 50);
        assert!(
            p < 0.001,
            "disjoint distributions should be wildly significant: {p}"
        );
    }

    #[test]
    fn psi_zero_for_identical_distributions() {
        let xs: Vec<f64> = (0..100).map(|i| (i % 20) as f64).collect();
        let value = psi(&xs, &xs, 10).unwrap();
        assert!(value.abs() < 1e-9, "PSI of identical data ≈ 0, got {value}");
    }

    #[test]
    fn psi_large_for_shifted_distribution() {
        let base: Vec<f64> = (0..200).map(|i| (i % 10) as f64).collect();
        let shifted: Vec<f64> = (0..200).map(|i| 100.0 + (i % 10) as f64).collect();
        let value = psi(&base, &shifted, 10).unwrap();
        assert!(
            value > 0.2,
            "shifted population should exceed threshold, got {value}"
        );
    }

    #[test]
    fn psi_none_when_baseline_too_small() {
        assert_eq!(psi(&[1.0, 2.0, 3.0], &[1.0, 2.0], 10), None);
    }

    #[test]
    fn chi2_zero_for_identical_category_mix() {
        let counts: BTreeMap<String, usize> = [("a".to_string(), 10), ("b".to_string(), 30)]
            .into_iter()
            .collect();
        let (stat, dof) = chi2_categorical(&counts, &counts).unwrap();
        assert!(stat.abs() < 1e-9, "identical mix ⇒ χ²≈0, got {stat}");
        assert_eq!(dof, 1);
    }

    #[test]
    fn chi2_flags_new_category() {
        let base: BTreeMap<String, usize> = [("a".to_string(), 50), ("b".to_string(), 50)]
            .into_iter()
            .collect();
        let cur: BTreeMap<String, usize> = [("a".to_string(), 40), ("c".to_string(), 60)]
            .into_iter()
            .collect();
        let (stat, _) = chi2_categorical(&base, &cur).unwrap();
        assert!(
            stat > 10.0,
            "a brand-new dominant category should spike χ², got {stat}"
        );
    }

    #[test]
    fn chi2_none_when_either_side_empty() {
        let nonempty: BTreeMap<String, usize> = [("a".to_string(), 5)].into_iter().collect();
        let empty: BTreeMap<String, usize> = BTreeMap::new();
        assert_eq!(chi2_categorical(&nonempty, &empty), None);
        assert_eq!(chi2_categorical(&empty, &nonempty), None);
        assert_eq!(chi2_categorical(&empty, &empty), None);
    }

    #[test]
    fn chi2_pvalue_small_for_large_stat() {
        assert!(chi2_pvalue(100.0, 1) < 0.001);
        assert!(chi2_pvalue(0.0, 1) > 0.99);
    }

    fn baseline_vs_current(b: Vec<Column>, c: Vec<Column>) -> (RecordSet, RecordSet) {
        (
            RecordSet::new("base", "t", b),
            RecordSet::new("cur", "t", c),
        )
    }

    #[test]
    fn ks_detector_absent_without_baseline() {
        let cur = RecordSet::new("-", "t", vec![ncol("x", &[1.0; 30])]);
        let mut out = Report::new();
        KsDetector.detect(
            &ScanContext::single(&cur),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(out.findings.is_empty());
        assert_eq!(out.absent.len(), 1);
        assert_eq!(out.absent[0].detector, "dist.ks");
    }

    #[test]
    fn ks_detector_flags_shift_with_baseline() {
        let base_vals: Vec<f64> = (0..40).map(|i| (i % 10) as f64).collect();
        let cur_vals: Vec<f64> = (0..40).map(|i| 50.0 + (i % 10) as f64).collect();
        let (base, cur) =
            baseline_vs_current(vec![ncol("x", &base_vals)], vec![ncol("x", &cur_vals)]);
        let mut out = Report::new();
        KsDetector.detect(
            &ScanContext::compared(&base, &cur),
            &DetectConfig::default(),
            &mut out,
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].detector, "dist.ks");
        assert!(matches!(out.findings[0].handle, Handle::Dist { .. }));
    }

    #[test]
    fn ks_detector_clean_when_distributions_match() {
        let vals: Vec<f64> = (0..40).map(|i| (i % 10) as f64).collect();
        let (base, cur) = baseline_vs_current(vec![ncol("x", &vals)], vec![ncol("x", &vals)]);
        let mut out = Report::new();
        KsDetector.detect(
            &ScanContext::compared(&base, &cur),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(out.findings.is_empty(), "identical data is not drift");
        assert!(out.absent.is_empty(), "the detector ran; it is not absent");
    }

    #[test]
    fn chi2_detector_flags_category_drift() {
        let base = scol("g", &["a", "a", "a", "b", "b", "b", "a", "b", "a", "b"]);
        let cur = scol("g", &["c", "c", "c", "c", "c", "b", "c", "c", "c", "c"]);
        let (b, c) = baseline_vs_current(vec![base], vec![cur]);
        let mut out = Report::new();
        Chi2Detector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].detector, "dist.chi2");
    }

    // ----- exact-value pins for the pure math (kill arithmetic mutants) -----

    #[test]
    fn ks_q_exact_values() {
        assert!((ks_q(1.0) - 0.26999967167735456).abs() < 1e-15);
        assert!((ks_q(0.5) - 0.9639452436648751).abs() < 1e-15);
    }

    #[test]
    fn ks_pvalue_exact_value() {
        // en = sqrt(2500/100) = 5; λ = (5 + 0.12 + 0.11/5)·0.5; Q(λ) ≈ 3.6276e-6.
        assert!((ks_pvalue(0.5, 50, 50) - 3.627616200654517e-6).abs() < 1e-15);
    }

    #[test]
    fn quantile_edges_exact() {
        let b: Vec<f64> = (0..10).map(|i| i as f64).collect();
        assert_eq!(quantile_edges(&b, 2), vec![4.5]);
    }

    #[test]
    fn bin_counts_exact_and_asymmetric() {
        // edge 2.5: values {0,1,2} → bin 0, value 10 → bin 1. Asymmetric so a
        // flipped comparator gives [1, 3] instead of [3, 1].
        assert_eq!(bin_counts(&[0.0, 1.0, 2.0, 10.0], &[2.5], 2), vec![3, 1]);
    }

    #[test]
    fn psi_exact_shift_value() {
        let base: Vec<f64> = (0..20).map(|i| (i % 10) as f64).collect();
        let shifted: Vec<f64> = (0..20).map(|i| 100.0 + (i % 10) as f64).collect();
        assert_eq!(psi(&base, &base, 5), Some(0.0));
        let v = psi(&base, &shifted, 5).unwrap();
        assert!((v - 7.3652319366).abs() < 1e-9, "got {v}");
    }

    #[test]
    fn psi_bin_boundaries_are_respected() {
        // bins == 2 is valid; baseline length == bins is the minimum that bins.
        assert!(psi(&[1.0, 2.0, 3.0, 4.0], &[1.0, 2.0, 3.0, 4.0], 2).is_some());
        assert!(psi(&[1.0, 2.0], &[1.0, 2.0], 2).is_some()); // len == bins
        assert_eq!(psi(&[1.0], &[1.0, 2.0], 2), None); // len < bins
        assert_eq!(psi(&[1.0, 2.0, 3.0], &[1.0], 1), None); // bins < 2
    }

    #[test]
    fn chi2_categorical_exact_stat() {
        let base: BTreeMap<String, usize> = [("a".to_string(), 10), ("b".to_string(), 30)]
            .into_iter()
            .collect();
        let cur: BTreeMap<String, usize> = [("a".to_string(), 20), ("b".to_string(), 20)]
            .into_iter()
            .collect();
        // expected a=10,b=30; (20-10)²/10 + (20-30)²/30 = 10 + 3.333… = 13.333…
        let (stat, dof) = chi2_categorical(&base, &cur).unwrap();
        assert!((stat - 13.333333333333334).abs() < 1e-9, "got {stat}");
        assert_eq!(dof, 1);
    }

    // ----- detector boundary & confidence behavior -----

    #[test]
    fn ks_detector_confidence_is_calibrated_from_pvalue() {
        // Mild drift (shift 12) → flagged with a *meaningful* p-value, so the
        // calibrated confidence is the unified undercut mapping of (p vs alpha),
        // distinguishable from a degenerate constant.
        let base: Vec<f64> = (0..40).map(|i| i as f64).collect();
        let cur: Vec<f64> = (0..40).map(|i| i as f64 + 12.0).collect();
        let (b, c) = baseline_vs_current(vec![ncol("x", &base)], vec![ncol("x", &cur)]);
        let cfg = DetectConfig::default();
        let mut out = Report::new();
        KsDetector.detect(&ScanContext::compared(&b, &c), &cfg, &mut out);
        assert_eq!(out.findings.len(), 1);
        let p = ks_pvalue(ks_statistic(&base, &cur).unwrap(), 40, 40);
        let expected = calibrate::from_undercut(p, cfg.dist_alpha);
        assert!((out.findings[0].confidence - expected).abs() < 1e-12);
        // p well below alpha ⇒ confidence above the at-threshold 0.5.
        assert!(out.findings[0].confidence > 0.5);
    }

    #[test]
    fn ks_detector_runs_at_exactly_min_n() {
        let n = DetectConfig::default().dist_min_n; // 20
        let base: Vec<f64> = (0..n).map(|i| i as f64).collect();
        let cur: Vec<f64> = (0..n).map(|i| i as f64 + 50.0).collect();
        let (b, c) = baseline_vs_current(vec![ncol("x", &base)], vec![ncol("x", &cur)]);
        let mut out = Report::new();
        KsDetector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(
            !out.findings.is_empty(),
            "exactly min_n values must be assessed"
        );
        assert!(out.absent.is_empty());
    }

    #[test]
    fn ks_detector_skips_when_one_side_below_min_n() {
        let base: Vec<f64> = (0..20).map(|i| i as f64).collect();
        let cur: Vec<f64> = (0..5).map(|i| i as f64).collect(); // below min_n
        let (b, c) = baseline_vs_current(vec![ncol("x", &base)], vec![ncol("x", &cur)]);
        let mut out = Report::new();
        KsDetector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(out.findings.is_empty());
        assert!(out.absent.iter().any(|a| a.detector == "dist.ks"));
    }

    #[test]
    fn psi_detector_flags_shift_and_is_not_absent() {
        let base: Vec<f64> = (0..200).map(|i| (i % 10) as f64).collect();
        let cur: Vec<f64> = (0..200).map(|i| 100.0 + (i % 10) as f64).collect();
        let (b, c) = baseline_vs_current(vec![ncol("x", &base)], vec![ncol("x", &cur)]);
        let mut out = Report::new();
        PsiDetector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].detector, "dist.psi");
        assert!(out.absent.is_empty());
    }

    #[test]
    fn psi_detector_clean_when_distributions_match() {
        let vals: Vec<f64> = (0..200).map(|i| (i % 10) as f64).collect();
        let (b, c) = baseline_vs_current(vec![ncol("x", &vals)], vec![ncol("x", &vals)]);
        let mut out = Report::new();
        PsiDetector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(out.findings.is_empty());
        assert!(out.absent.is_empty(), "it ran; not absent");
    }

    #[test]
    fn psi_and_chi2_absent_without_baseline() {
        let cur = RecordSet::new("-", "t", vec![ncol("x", &[1.0; 30])]);
        for det in [
            Box::new(PsiDetector) as Box<dyn Detector>,
            Box::new(Chi2Detector),
        ] {
            let mut out = Report::new();
            det.detect(
                &ScanContext::single(&cur),
                &DetectConfig::default(),
                &mut out,
            );
            assert!(out.findings.is_empty());
            assert_eq!(out.absent.len(), 1);
        }
    }

    #[test]
    fn psi_absent_when_no_shared_numeric_column() {
        let (b, c) =
            baseline_vs_current(vec![scol("g", &["a", "b"])], vec![scol("g", &["a", "b"])]);
        let mut out = Report::new();
        PsiDetector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(out.absent.iter().any(|a| a.detector == "dist.psi"));
    }

    #[test]
    fn chi2_detector_confidence_is_one_minus_pvalue() {
        // 50/50 → 40/60 gives χ²=4.0, p≈0.0455 (flagged), confidence≈0.954.
        let rep = |a: usize, b: usize| {
            let mut v = Vec::new();
            v.extend(std::iter::repeat_n(Value::Str("a".into()), a));
            v.extend(std::iter::repeat_n(Value::Str("b".into()), b));
            Column::new("g", v)
        };
        let (base, cur) = baseline_vs_current(vec![rep(50, 50)], vec![rep(40, 60)]);
        let mut out = Report::new();
        Chi2Detector.detect(
            &ScanContext::compared(&base, &cur),
            &DetectConfig::default(),
            &mut out,
        );
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.findings[0].confidence < 0.99,
            "moderate p ⇒ confidence < 0.99"
        );
        assert!(out.absent.is_empty());
    }

    #[test]
    fn chi2_absent_when_no_shared_categorical() {
        let (b, c) = baseline_vs_current(vec![ncol("x", &[1.0; 5])], vec![ncol("x", &[1.0; 5])]);
        let mut out = Report::new();
        Chi2Detector.detect(
            &ScanContext::compared(&b, &c),
            &DetectConfig::default(),
            &mut out,
        );
        assert!(out.absent.iter().any(|a| a.detector == "dist.chi2"));
    }

    proptest! {
        // KS D statistic is symmetric in its arguments.
        #[test]
        fn ks_is_symmetric(seed in 0u64..500) {
            let a: Vec<f64> = (0..30).map(|i| ((i as u64 * 7 + seed) % 50) as f64).collect();
            let b: Vec<f64> = (0..25).map(|i| ((i as u64 * 13 + seed) % 50) as f64).collect();
            prop_assert_eq!(ks_statistic(&a, &b), ks_statistic(&b, &a));
        }

        // KS D is always a probability-scale value in [0, 1].
        #[test]
        fn ks_in_unit_interval(s1 in 0u64..500, s2 in 0u64..500) {
            let a: Vec<f64> = (0..40).map(|i| ((i as u64).wrapping_mul(s1.max(1)) % 97) as f64).collect();
            let b: Vec<f64> = (0..40).map(|i| ((i as u64).wrapping_mul(s2.max(1)) % 97) as f64).collect();
            let d = ks_statistic(&a, &b).unwrap();
            prop_assert!((0.0..=1.0).contains(&d));
        }

        // PSI is non-negative and zero only for matching binned mass.
        #[test]
        fn psi_is_nonnegative(seed in 0u64..500) {
            let base: Vec<f64> = (0..100).map(|i| ((i as u64 * 3 + seed) % 40) as f64).collect();
            let cur: Vec<f64> = (0..100).map(|i| ((i as u64 * 5 + seed) % 40) as f64).collect();
            if let Some(v) = psi(&base, &cur, 10) {
                prop_assert!(v >= -1e-9, "PSI must be non-negative, got {}", v);
            }
        }
    }
}
