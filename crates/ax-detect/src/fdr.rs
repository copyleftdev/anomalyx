//! Multiplicity control for per-cell significance tests — Benjamini–Hochberg
//! false-discovery-rate (FDR) control.
//!
//! The point detector tests every numeric cell of a column for being an outlier.
//! With thousands of cells a fixed per-cell cutoff flags many cells by chance
//! alone. Benjamini–Hochberg bounds the *expected proportion of false discoveries*
//! among the cells it flags at a level `q`, adapting the cutoff to how many cells
//! were tested — so a column that is really just noise stops contributing chance
//! flags, while a column with genuine outliers keeps them.
//!
//! Both routines are deterministic (a sort and a single sweep); no RNG, no
//! wall-clock, order-independent in the rejection set they induce.

use statrs::function::erf::erfc;
use std::f64::consts::SQRT_2;

/// Two-sided p-value of a modified z-score under the standard-normal null:
/// `P(|Z| ≥ |modz|) = erfc(|modz| / √2)`. `modz == 0` → `1.0`; a large `|modz|`
/// → `0.0`. The Iglewicz–Hoaglin modified z-score is scaled to be ~`N(0, 1)`
/// under the null, which is what makes this mapping meaningful.
pub fn two_sided_p(modz: f64) -> f64 {
    erfc(modz.abs() / SQRT_2)
}

/// Benjamini–Hochberg rejection cutoff for `pvals` at FDR level `q`.
///
/// Returns the largest order statistic `p_(k)` (ranks `k = 1..=m`) satisfying
/// `p_(k) ≤ (k / m)·q`; reject every hypothesis whose p-value is `≤` that cutoff.
/// `None` means nothing is significant (reject none). With this convention the
/// expected false-discovery proportion among the rejected set is at most `q`
/// (for independent or positively-dependent tests).
pub fn benjamini_hochberg(pvals: &[f64], q: f64) -> Option<f64> {
    let m = pvals.len();
    if m == 0 {
        return None;
    }
    let mut sorted = pvals.to_vec();
    sorted.sort_by(f64::total_cmp);
    let m_f = m as f64;
    let mut cutoff = None;
    for (i, &p) in sorted.iter().enumerate() {
        let rank = (i + 1) as f64;
        if p <= (rank / m_f) * q {
            cutoff = Some(p);
        }
    }
    cutoff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_sided_p_known_values() {
        // erfc(0) = 1; a zero score is maximally unremarkable.
        assert_eq!(two_sided_p(0.0), 1.0);
        // Symmetric in sign.
        assert_eq!(two_sided_p(2.5), two_sided_p(-2.5));
        // ~1.96 ⇒ the familiar two-sided 0.05; 3.5 ⇒ ~4.65e-4.
        assert!((two_sided_p(1.959964) - 0.05).abs() < 1e-4);
        assert!((two_sided_p(3.5) - 4.6520e-4).abs() < 1e-6);
        // Monotone decreasing in |modz|.
        assert!(two_sided_p(4.0) < two_sided_p(3.0));
    }

    #[test]
    fn bh_empty_is_none() {
        assert_eq!(benjamini_hochberg(&[], 0.05), None);
    }

    #[test]
    fn bh_all_null_rejects_nothing() {
        // Uniform-ish large p-values: none satisfy p ≤ (k/m)·q.
        let p = [0.40, 0.55, 0.70, 0.85, 0.99];
        assert_eq!(benjamini_hochberg(&p, 0.05), None);
    }

    #[test]
    fn bh_rejects_the_clearly_significant_only() {
        // One tiny p among noise: rejected, and the cutoff is that p-value.
        let p = [0.0001, 0.40, 0.55, 0.70, 0.99];
        let cutoff = benjamini_hochberg(&p, 0.05).unwrap();
        assert_eq!(cutoff, 0.0001);
        // Count how many are rejected at that cutoff.
        let rejected = p.iter().filter(|&&x| x <= cutoff).count();
        assert_eq!(rejected, 1);
    }

    #[test]
    fn bh_step_up_rejects_a_run_not_just_the_smallest() {
        // m = 5, q = 0.05. Sorted p: .009 .011 .012 .30 .40 ;
        // thresholds k/m·q: .01 .02 .03 .04 .05.
        //   k=1 .009≤.01 ✓  k=2 .011≤.02 ✓  k=3 .012≤.03 ✓  k=4 .30≤.04 ✗  k=5 ✗
        // The largest k with p_(k) ≤ (k/m)q is k=3 ⇒ cutoff = .012, rejecting the
        // first three. This is the step-up property: more than just p_(1).
        let p = [0.40, 0.011, 0.30, 0.009, 0.012];
        let cutoff = benjamini_hochberg(&p, 0.05).unwrap();
        assert_eq!(cutoff, 0.012);
        assert_eq!(p.iter().filter(|&&x| x <= cutoff).count(), 3);
    }

    #[test]
    fn bh_is_order_independent() {
        let a = [0.04, 0.011, 0.03, 0.009, 0.012];
        let mut b = a;
        b.reverse();
        assert_eq!(benjamini_hochberg(&a, 0.05), benjamini_hochberg(&b, 0.05));
    }

    #[test]
    fn bh_larger_q_rejects_at_least_as_much() {
        let p = [0.001, 0.02, 0.03, 0.2, 0.5, 0.6];
        let lo = benjamini_hochberg(&p, 0.01).map_or(0, |c| p.iter().filter(|&&x| x <= c).count());
        let hi = benjamini_hochberg(&p, 0.10).map_or(0, |c| p.iter().filter(|&&x| x <= c).count());
        assert!(
            hi >= lo,
            "a larger FDR level cannot reject fewer ({hi} >= {lo})"
        );
    }
}
