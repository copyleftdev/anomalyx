//! # ax-validate — proving the math against NIST
//!
//! anomalyx's detectors all rest on a small set of deterministic reductions
//! ([`ax_core::det`]). This crate validates those against the **NIST Statistical
//! Reference Datasets (StRD)** — the canonical, certified-to-15-digits truth for
//! univariate summary statistics — so "mathematically correct" is a checked
//! claim, not an assertion. The datasets are vendored under `data/strd/` and
//! embedded at compile time, so validation runs offline and reproducibly.
//!
//! The certified values come straight from NIST:
//! <https://www.itl.nist.gov/div898/strd/univ/homepage.html>.

/// The certified summary statistics and raw observations of one StRD dataset.
#[derive(Debug, Clone)]
pub struct Strd {
    pub name: String,
    /// Certified sample mean.
    pub mean: f64,
    /// Certified sample standard deviation (denominator `n − 1`).
    pub std: f64,
    /// Certified lag-1 autocorrelation coefficient.
    pub autocorr: f64,
    /// Certified number of observations.
    pub nobs: usize,
    /// The raw observations, in file order.
    pub data: Vec<f64>,
}

/// Parses the standard NIST StRD univariate `.dat` layout: a documentation
/// header carrying the certified values (each on a line keyed by a trailing
/// `label:` token), an all-dashes separator, then one observation per line.
///
/// Panics on a malformed file — these are vendored fixtures, so a parse failure
/// is a build-time bug to fix, not a runtime condition to handle.
pub fn parse(name: &str, text: &str) -> Strd {
    // `str::lines` already strips the `\r` of CRLF endings.
    let lines: Vec<&str> = text.lines().collect();

    // The certified value is the first whitespace token after the final colon
    // on the line carrying `keyword` (e.g. "... ybar:  -177.4350  (exact)").
    let certified = |keyword: &str| -> f64 {
        let line = lines
            .iter()
            .find(|l| l.contains(keyword))
            .unwrap_or_else(|| panic!("{name}: no line containing '{keyword}'"));
        let after_colon = line
            .rsplit(':')
            .next()
            .unwrap_or_else(|| panic!("{name}: no ':' on '{keyword}' line"));
        after_colon
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("{name}: no value after '{keyword}:'"))
            .parse()
            .unwrap_or_else(|e| panic!("{name}: bad '{keyword}' value: {e}"))
    };

    let mean = certified("Sample Mean");
    let std = certified("Standard Deviation");
    let autocorr = certified("Autocorrelation");
    let nobs = certified("Number of Observations") as usize;

    // Data starts after the all-dashes separator line.
    let sep = lines
        .iter()
        .position(|l| {
            let t = l.trim();
            t.len() >= 3 && t.bytes().all(|b| b == b'-')
        })
        .unwrap_or_else(|| panic!("{name}: no dashed separator before data"));
    // Strict parse: every non-blank line after the separator must be numeric.
    // (A lenient `filter_map(...ok())` would mask a mis-detected separator.)
    let data: Vec<f64> = lines[sep + 1..]
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| {
            l.parse::<f64>()
                .unwrap_or_else(|_| panic!("{name}: non-numeric data line {l:?}"))
        })
        .collect();

    assert_eq!(
        data.len(),
        nobs,
        "{name}: parsed {} observations, certified {nobs}",
        data.len()
    );

    Strd {
        name: name.to_string(),
        mean,
        std,
        autocorr,
        nobs,
        data,
    }
}

/// The NIST StRD univariate datasets, vendored and embedded. Ordered roughly by
/// numerical difficulty; the `NumAcc*` set is purpose-built to break naïve
/// statistics code.
pub const DATASETS: &[(&str, &str)] = &[
    ("PiDigits", include_str!("../data/strd/PiDigits.dat")),
    ("Lottery", include_str!("../data/strd/Lottery.dat")),
    ("Lew", include_str!("../data/strd/Lew.dat")),
    ("Mavro", include_str!("../data/strd/Mavro.dat")),
    ("Michelso", include_str!("../data/strd/Michelso.dat")),
    ("NumAcc1", include_str!("../data/strd/NumAcc1.dat")),
    ("NumAcc2", include_str!("../data/strd/NumAcc2.dat")),
    ("NumAcc3", include_str!("../data/strd/NumAcc3.dat")),
    ("NumAcc4", include_str!("../data/strd/NumAcc4.dat")),
];

/// Parses every embedded dataset.
pub fn datasets() -> Vec<Strd> {
    DATASETS.iter().map(|(n, t)| parse(n, t)).collect()
}

/// NIST's "log relative error": the number of correct significant digits in
/// `computed` relative to `certified`. Higher is better; an exact match is
/// reported as `f64::INFINITY`. This is the standard StRD accuracy metric.
pub fn correct_digits(computed: f64, certified: f64) -> f64 {
    if computed == certified {
        return f64::INFINITY;
    }
    let rel = if certified != 0.0 {
        ((computed - certified) / certified).abs()
    } else {
        computed.abs()
    };
    if rel == 0.0 {
        f64::INFINITY
    } else {
        -rel.log10()
    }
}

/// The textbook one-pass ("sum of squares") variance, kept here precisely to
/// demonstrate what anomalyx deliberately does *not* do: on data with a large
/// mean and small spread it suffers catastrophic cancellation. Contrast with
/// [`ax_core::det::variance`], which is two-pass and compensated.
pub fn naive_one_pass_variance(xs: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let sum: f64 = xs.iter().sum();
    let sum_sq: f64 = xs.iter().map(|x| x * x).sum();
    (sum_sq - sum * sum / n) / (n - 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dataset_parses_with_the_certified_count() {
        for d in datasets() {
            assert_eq!(d.data.len(), d.nobs, "{}", d.name);
            assert!(d.std >= 0.0, "{}", d.name);
        }
    }

    #[test]
    fn correct_digits_behaves() {
        assert!(correct_digits(1.0, 1.0).is_infinite());
        // one part in 1000 off ⇒ ~3 correct digits
        assert!((correct_digits(1.001, 1.0) - 3.0).abs() < 0.01);
    }
}
