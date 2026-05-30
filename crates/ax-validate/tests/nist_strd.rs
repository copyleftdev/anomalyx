//! Validation against the NIST StRD certified values.
//!
//! These tests turn "anomalyx is mathematically correct" into a checked fact:
//! the deterministic reductions every detector relies on are compared against
//! NIST's certified-to-15-digits summary statistics, scored by NIST's own
//! log-relative-error (number of correct significant digits).

use ax_core::det;
use ax_validate::{correct_digits, datasets, naive_one_pass_variance};

/// Real-world datasets where the data is well-conditioned enough to expect
/// near-machine-precision on the standard deviation.
const WELL_CONDITIONED: &[&str] = &["PiDigits", "Lottery", "Lew", "Mavro", "Michelso"];

#[test]
fn certified_mean_matches_to_full_precision() {
    for d in datasets() {
        let mean = det::mean(&d.data).expect("non-empty");
        let digits = correct_digits(mean, d.mean);
        assert!(
            digits >= 15.0,
            "{}: mean has only {digits:.2} correct digits (computed {mean}, certified {})",
            d.name,
            d.mean
        );
    }
}

#[test]
fn certified_std_dev_matches() {
    for d in datasets() {
        let std = det::std_dev(&d.data).expect(">= 2 points");
        let digits = correct_digits(std, d.std);
        // NumAcc3/NumAcc4 are bounded near 8 digits by the f64 representation of
        // their inputs (mean ≈ 1e6–1e7, spread 0.1) — NIST expects no more.
        assert!(
            digits >= 8.0,
            "{}: std has only {digits:.2} correct digits (computed {std}, certified {})",
            d.name,
            d.std
        );
        if WELL_CONDITIONED.contains(&d.name.as_str()) {
            assert!(
                digits >= 13.0,
                "{}: well-conditioned std should reach ≥13 digits, got {digits:.2}",
                d.name
            );
        }
    }
}

#[test]
fn compensated_reductions_beat_the_naive_formula() {
    // The whole point of the determinism-and-precision design: on the
    // ill-conditioned NumAcc datasets the textbook one-pass variance loses
    // almost every digit, while the compensated two-pass tracks NIST closely.
    for name in ["NumAcc3", "NumAcc4"] {
        let d = datasets().into_iter().find(|d| d.name == name).unwrap();
        let ours = correct_digits(det::std_dev(&d.data).unwrap(), d.std);
        let naive = correct_digits(naive_one_pass_variance(&d.data).max(0.0).sqrt(), d.std);
        assert!(
            naive < 2.0,
            "{name}: naive formula should be badly wrong, got {naive:.2} digits"
        );
        assert!(
            ours >= 8.0,
            "{name}: compensated should hold ≥8 digits, got {ours:.2}"
        );
        assert!(
            ours - naive >= 5.0,
            "{name}: compensated ({ours:.2}) should beat naive ({naive:.2}) by ≥5 digits"
        );
    }
}

#[test]
fn numacc1_is_exact() {
    // Constructed to have exact integer/half answers; we should match bit-for-bit.
    let d = datasets()
        .into_iter()
        .find(|d| d.name == "NumAcc1")
        .unwrap();
    assert_eq!(det::mean(&d.data).unwrap(), 10000002.0);
    assert_eq!(det::std_dev(&d.data).unwrap(), 1.0);
}
