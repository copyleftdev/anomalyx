//! Deterministic numeric reductions.
//!
//! The article's hard line: *"Determinism is not just a testing preference. It
//! is user experience for agents."* Floating-point addition is neither
//! associative nor commutative, so the order in which a column is summed can
//! change the result. Every reduction here is **order-independent**: inputs are
//! sorted by [`f64::total_cmp`] before accumulation, then summed with
//! compensated (Kahan–Neumaier) addition. Same multiset of values → identical
//! bits, regardless of how the caller arranged them.
//!
//! NaNs are never silently folded into a statistic; callers strip them first
//! (see [`finite`]). This keeps "honest absence" honest: a column that is all
//! NaN yields `None`, not a fabricated `0.0`.

/// Returns the subset of `xs` that is finite (no NaN, no ±∞), preserving order.
pub fn finite(xs: &[f64]) -> Vec<f64> {
    xs.iter().copied().filter(|x| x.is_finite()).collect()
}

/// Order-independent compensated sum.
///
/// Values are sorted by [`f64::total_cmp`] so that any permutation of the same
/// inputs produces the same bit pattern, then accumulated with the Neumaier
/// variant of Kahan summation to bound rounding error.
pub fn det_sum(xs: &[f64]) -> f64 {
    let mut sorted: Vec<f64> = xs.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mut sum = 0.0_f64;
    let mut comp = 0.0_f64; // running compensation
    for &x in &sorted {
        let t = sum + x;
        if sum.abs() >= x.abs() {
            comp += (sum - t) + x;
        } else {
            comp += (x - t) + sum;
        }
        sum = t;
    }
    sum + comp
}

/// Arithmetic mean, or `None` if `xs` is empty.
pub fn mean(xs: &[f64]) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    Some(det_sum(xs) / xs.len() as f64)
}

/// Sample variance (Bessel-corrected, denominator `n - 1`).
///
/// Returns `None` for fewer than two values, where sample variance is undefined.
pub fn variance(xs: &[f64]) -> Option<f64> {
    let n = xs.len();
    if n < 2 {
        return None;
    }
    let m = mean(xs)?;
    let sq: Vec<f64> = xs.iter().map(|x| (x - m) * (x - m)).collect();
    Some(det_sum(&sq) / (n - 1) as f64)
}

/// Sample standard deviation. `None` for fewer than two values.
pub fn std_dev(xs: &[f64]) -> Option<f64> {
    variance(xs).map(f64::sqrt)
}

/// Quantile via linear interpolation (the "type 7" / NumPy default method).
///
/// `q` is clamped to `[0, 1]`. Returns `None` for an empty slice.
pub fn quantile(xs: &[f64], q: f64) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let q = q.clamp(0.0, 1.0);
    let mut sorted: Vec<f64> = xs.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    if n == 1 {
        return Some(sorted[0]);
    }
    let pos = q * (n - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return Some(sorted[lo]);
    }
    let frac = pos - lo as f64;
    Some(sorted[lo] * (1.0 - frac) + sorted[hi] * frac)
}

/// Median (the 0.5 quantile).
pub fn median(xs: &[f64]) -> Option<f64> {
    quantile(xs, 0.5)
}

/// Median absolute deviation, scaled to be a consistent estimator of σ for
/// normal data (factor `1.4826`). `None` for an empty slice.
pub fn mad(xs: &[f64]) -> Option<f64> {
    let med = median(xs)?;
    let dev: Vec<f64> = xs.iter().map(|x| (x - med).abs()).collect();
    median(&dev).map(|m| 1.4826 * m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn det_sum_is_permutation_invariant() {
        let a = [1.0, 2.0, 3.0, 1e16, -1e16, 4.0];
        let mut b = a;
        b.reverse();
        assert_eq!(det_sum(&a).to_bits(), det_sum(&b).to_bits());
    }

    #[test]
    fn mean_of_empty_is_none() {
        assert_eq!(mean(&[]), None);
    }

    #[test]
    fn variance_needs_two() {
        assert_eq!(variance(&[5.0]), None);
        assert_eq!(variance(&[2.0, 4.0]), Some(2.0));
    }

    #[test]
    fn quantile_endpoints_and_middle() {
        let xs = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(quantile(&xs, 0.0), Some(1.0));
        assert_eq!(quantile(&xs, 1.0), Some(4.0));
        assert_eq!(median(&xs), Some(2.5));
    }

    #[test]
    fn mad_of_constant_is_zero() {
        assert_eq!(mad(&[7.0, 7.0, 7.0]), Some(0.0));
    }
}
