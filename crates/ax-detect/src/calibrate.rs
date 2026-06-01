//! Unified confidence calibration.
//!
//! Every detector ultimately reduces to "a statistic crossed a firing
//! threshold." To make a confidence of `0.9` mean the same *strength of evidence*
//! regardless of which detector produced it, confidence is a single shared
//! logistic of how far the statistic sits past its threshold, measured
//! **relatively** so the detector's units cancel: right at the threshold → `0.5`,
//! rising toward `1.0` as the statistic grows more extreme. A finding at "twice
//! its threshold" earns the same confidence whether it came from a modified
//! z-score, a KS p-value, a PSI, or an inter-arrival coefficient of variation —
//! which is what lets severity (and `--top` / `--min-severity`) rank findings
//! from different detectors on one scale.

/// Logistic steepness in the relative excess. Larger ⇒ confidence climbs faster
/// past the threshold. Tuned so ~2× past threshold reads as "high" and ~3×+ as
/// "critical" on the severity ladder. A fixed calibration constant (like the
/// modified-z `MODZ_K`), not a tunable — changing it is a tool-version change.
const STEEPNESS: f64 = 2.0;

fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Confidence for a detector that fires when `statistic` rises **above** a
/// positive `threshold` (modified z-score, CUSUM shift, PSI, null fraction):
/// logistic in the relative excess `statistic/threshold − 1`. At the threshold
/// → `0.5`; far above → → `1.0`.
pub fn from_exceedance(statistic: f64, threshold: f64) -> f64 {
    if threshold <= 0.0 {
        // A zero (or invalid) bar: any positive statistic is maximally past it.
        return if statistic > 0.0 { 1.0 } else { 0.5 };
    }
    logistic(STEEPNESS * (statistic / threshold - 1.0))
}

/// Confidence for a detector that fires when `statistic` falls **below** a
/// positive `threshold` (a p-value under alpha, a CV under the max): logistic in
/// the relative excess `threshold/statistic − 1`. At the threshold → `0.5`; as
/// the statistic approaches `0` → → `1.0` (maximally significant).
pub fn from_undercut(statistic: f64, threshold: f64) -> f64 {
    if statistic <= 0.0 {
        // p == 0 / CV == 0: as far past the bar as it is possible to be.
        return 1.0;
    }
    if threshold <= 0.0 {
        return 0.0;
    }
    logistic(STEEPNESS * (threshold / statistic - 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    // logistic(2·1) = 1/(1+e^-2) ≈ 0.880797; the canonical "2× past threshold".
    const TWO_X: f64 = 0.8807970779778823;

    #[test]
    fn at_threshold_is_one_half() {
        assert_eq!(from_exceedance(3.5, 3.5), 0.5);
        assert_eq!(from_exceedance(0.2, 0.2), 0.5);
        assert_eq!(from_undercut(0.05, 0.05), 0.5);
        assert_eq!(from_undercut(0.001, 0.001), 0.5);
    }

    #[test]
    fn exceedance_rises_above_threshold_falls_below() {
        assert!(from_exceedance(7.0, 3.5) > 0.5); // 2× ⇒ above 0.5
        assert!(from_exceedance(2.0, 3.5) < 0.5); // under the bar ⇒ below 0.5
        assert!(from_exceedance(10.0, 3.5) > from_exceedance(5.0, 3.5)); // monotone
    }

    #[test]
    fn undercut_rises_as_statistic_shrinks() {
        assert!(from_undercut(0.025, 0.05) > 0.5); // half the bar ⇒ above 0.5
        assert!(from_undercut(0.10, 0.05) < 0.5); // over the bar ⇒ below 0.5
        assert!(from_undercut(0.001, 0.05) > from_undercut(0.01, 0.05)); // monotone
    }

    #[test]
    fn boundaries_are_saturated_not_nan() {
        assert_eq!(from_undercut(0.0, 0.05), 1.0); // p == 0
        assert_eq!(from_undercut(0.0, 0.0), 1.0); // degenerate p == cutoff == 0
        assert_eq!(from_exceedance(1.0, 0.0), 1.0); // positive past a zero bar
        assert_eq!(from_exceedance(0.0, 0.0), 0.5);
        assert_eq!(from_undercut(0.5, 0.0), 0.0);
    }

    #[test]
    fn two_x_past_threshold_is_identical_across_directions_and_units() {
        // The comparability guarantee: "2× past the threshold" yields the same
        // confidence regardless of detector direction or units.
        let a = from_exceedance(7.0, 3.5); // 2× above (z-score-like)
        let b = from_exceedance(0.4, 0.2); // 2× above (PSI-like)
        let c = from_undercut(0.025, 0.05); // half the bar = 2× past (p-value-like)
        assert!((a - TWO_X).abs() < 1e-12);
        assert!((b - TWO_X).abs() < 1e-12);
        assert!((c - TWO_X).abs() < 1e-12);
    }

    #[test]
    fn stays_in_unit_interval() {
        for &(s, t) in &[(1e9, 3.5), (3.5, 3.5), (0.0, 3.5)] {
            let c = from_exceedance(s, t);
            assert!((0.0..=1.0).contains(&c));
        }
        for &(s, t) in &[(1e-12, 0.05), (0.05, 0.05), (1.0, 0.05)] {
            let c = from_undercut(s, t);
            assert!((0.0..=1.0).contains(&c));
        }
    }
}
