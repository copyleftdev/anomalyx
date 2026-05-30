//! Rigorous stress tests: determinism at scale on real data, and end-to-end
//! detector behavior against known ground truth.

use ax_core::finding::Handle;
use ax_core::{det, Column, RecordSet, Value};
use ax_detect::{DetectConfig, Registry, ScanContext};
use ax_validate::datasets;

/// Deterministic xorshift64* — a reproducible value source (the workflow ban on
/// `Math.random`/wall-clock applies; this is seeded and pure).
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// A value in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[test]
fn det_sum_is_permutation_invariant_on_real_nist_data() {
    // The determinism guarantee, exercised on 5000 real observations and more:
    // the order-independent sum is bit-for-bit identical under reversal and
    // rotations, on every certified dataset.
    for d in datasets() {
        let base = det::det_sum(&d.data).to_bits();

        let mut reversed = d.data.clone();
        reversed.reverse();
        assert_eq!(
            det::det_sum(&reversed).to_bits(),
            base,
            "{}: reversed",
            d.name
        );

        for rot in [1usize, 7, 101, 999] {
            if d.data.len() > rot {
                let mut rotated = d.data.clone();
                rotated.rotate_left(rot);
                assert_eq!(
                    det::det_sum(&rotated).to_bits(),
                    base,
                    "{}: rotated by {rot}",
                    d.name
                );
            }
        }
    }
}

#[test]
fn point_detector_recovers_injected_outliers_exactly() {
    // Ground truth: a tight cluster of 1000 values with three planted extreme
    // outliers. A correct detector flags those three rows and nothing else
    // (precision = recall = 1).
    let n = 1000usize;
    let mut cells: Vec<Value> = (0..n)
        .map(|i| Value::Float(100.0 + ((i * 7919) % 11) as f64 * 0.01))
        .collect();
    let injected = [137usize, 503, 902];
    for &row in &injected {
        cells[row] = Value::Float(1.0e6);
    }
    let rs = RecordSet::new("-", "stress", vec![Column::new("v", cells)]);

    let report = Registry::default_set().run(&ScanContext::single(&rs), &DetectConfig::default());
    let mut flagged: Vec<usize> = report
        .findings
        .iter()
        .filter(|f| f.detector == "point.modz")
        .filter_map(|f| match &f.handle {
            Handle::Cell { row, .. } => Some(*row),
            _ => None,
        })
        .collect();
    flagged.sort_unstable();

    let mut expected = injected.to_vec();
    expected.sort_unstable();
    assert_eq!(flagged, expected, "exactly the planted outliers, no FP/FN");
}

#[test]
fn large_scan_is_byte_identical_across_runs() {
    // Determinism is UX for agents: a 40k-row scan with two numeric columns and
    // a categorical one must serialize identically on repeated runs.
    let n = 40_000usize;
    let mut rng = Rng(0x2545F4914F6CDD1D);
    let a: Vec<Value> = (0..n)
        .map(|_| Value::Float((rng.unit() * 100.0).round()))
        .collect();
    let b: Vec<Value> = (0..n).map(|_| Value::Float(rng.unit() * 5.0)).collect();
    let g: Vec<Value> = (0..n)
        .map(|i| Value::Str(["x", "y", "z"][i % 3].to_string()))
        .collect();
    let rs = RecordSet::new(
        "-",
        "stress",
        vec![
            Column::new("a", a),
            Column::new("b", b),
            Column::new("g", g),
        ],
    );

    let cfg = DetectConfig::default();
    let run = || {
        let report = Registry::default_set().run(&ScanContext::single(&rs), &cfg);
        serde_json::to_string(&report.findings).unwrap()
    };
    assert_eq!(run(), run(), "repeated scans must be byte-identical");
}

#[test]
fn detector_means_reproduce_certified_via_the_record_model() {
    // End-to-end through the public RecordSet/Column model (not just det::),
    // confirming the column projection feeding detectors is itself exact.
    for d in datasets() {
        let col = Column::new("v", d.data.iter().map(|&x| Value::Float(x)).collect());
        let mean = det::mean(&col.numeric()).unwrap();
        assert!(
            ax_validate::correct_digits(mean, d.mean) >= 15.0,
            "{}: column-projected mean lost precision",
            d.name
        );
    }
}
