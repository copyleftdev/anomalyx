//! Robust modified z-score primitives, shared by the point and contextual
//! detectors so the (mutation-pinned) scale selection and confidence mapping
//! live in exactly one place.
//!
//! Uses the Iglewicz–Hoaglin modified z-score `M = k·(x − center)/scale`, where
//! the scale is the median absolute deviation when it is positive and the
//! standard deviation otherwise. A genuinely constant sample has no scale and
//! yields `None` — nothing can deviate from it.

use ax_core::det;

/// Iglewicz–Hoaglin constant `1/Φ⁻¹(0.75)`, making the MAD-based score
/// comparable to a standard z-score for normal data.
pub const MODZ_K: f64 = 0.6745;

/// Robust `(center, scale, k)` for a sample: median + MAD (with constant `k`),
/// falling back to mean-relative σ (with `k = 1`) when MAD collapses. `None`
/// for an empty sample or one with no spread at all.
pub fn center_scale(xs: &[f64]) -> Option<(f64, f64, f64)> {
    let center = det::median(xs)?;
    let mad = det::mad(xs).unwrap_or(0.0);
    if mad > 0.0 {
        return Some((center, mad, MODZ_K));
    }
    match det::std_dev(xs) {
        Some(sd) if sd > 0.0 => Some((center, sd, 1.0)),
        _ => None,
    }
}

/// Absolute standardized deviation `|k·(x − center)/scale|`. Extracted so the
/// exact arithmetic (not just its sign) is pinned by tests.
pub fn score(x: f64, center: f64, scale: f64, k: f64) -> f64 {
    (k * (x - center) / scale).abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_exact_arithmetic() {
        assert_eq!(score(20.0, 10.0, 2.0, 0.5), 2.5);
        assert_eq!(score(0.0, 10.0, 2.0, 1.0), 5.0);
        assert_eq!(score(4.0, 10.0, 3.0, 1.0), 2.0);
    }

    #[test]
    fn center_scale_prefers_mad_then_sigma_then_none() {
        // spread data → MAD path, k = MODZ_K
        let (c, s, k) = center_scale(&[1.0, 2.0, 3.0, 4.0, 5.0]).unwrap();
        assert_eq!(c, 3.0);
        assert_eq!(k, MODZ_K);
        assert!(s > 0.0);
        // MAD collapses (mostly identical) but σ > 0 → σ path, k = 1.0
        let (_, s2, k2) = center_scale(&[5.0, 5.0, 5.0, 5.0, 99.0]).unwrap();
        assert_eq!(k2, 1.0);
        assert!(s2 > 0.0);
        // truly constant → no scale
        assert_eq!(center_scale(&[7.0, 7.0, 7.0]), None);
    }
}
