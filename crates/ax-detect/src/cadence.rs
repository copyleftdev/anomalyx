//! Cadence anomaly detector (metronomic regularity).
//!
//! Every other detector hunts irregularity; this one hunts the opposite — timing
//! that is *too* regular. Organic event streams (human clicks, real traffic)
//! have ragged inter-arrival gaps; automation tends toward a metronome. Given a
//! column of event times (rows in order), the dispersion of the consecutive
//! intervals is summarized by the coefficient of variation `CV = σ/μ`; a CV near
//! zero is the signature of an automated cadence.
//!
//! Which column means "time" is never guessed: the detector runs only on the
//! column named by `cadence_column`, and otherwise reports honest absence.

use crate::config::DetectConfig;
use crate::{Detector, Report, ScanContext};
use ax_core::det;
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, Finding};

#[derive(Debug, Default, Clone)]
pub struct CadenceDetector;

/// Consecutive forward differences of a value sequence.
pub fn intervals(xs: &[f64]) -> Vec<f64> {
    xs.windows(2).map(|w| w[1] - w[0]).collect()
}

/// Coefficient of variation `σ/μ` of `xs`. `None` unless there are at least two
/// values and the mean is strictly positive (a progressing series).
pub fn coefficient_of_variation(xs: &[f64]) -> Option<f64> {
    let mean = det::mean(xs)?;
    if mean <= 0.0 {
        return None;
    }
    let sd = det::std_dev(xs)?;
    Some(sd / mean)
}

impl Detector for CadenceDetector {
    fn id(&self) -> &'static str {
        "cad.regularity"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Cadence
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        let Some(name) = cfg.cadence_column.as_deref() else {
            out.mark_absent(
                self.id(),
                "cadence detection requires a time column (pass --cadence <COL>)",
            );
            return;
        };
        let Some(col) = ctx.current.column(name) else {
            out.mark_absent(self.id(), format!("column '{name}' not found"));
            return;
        };
        let values = col.numeric();
        let deltas = intervals(&values);
        if deltas.len() < cfg.cad_min_n {
            out.mark_absent(
                self.id(),
                format!("column '{name}' has fewer than {} intervals", cfg.cad_min_n),
            );
            return;
        }
        let Some(cv) = coefficient_of_variation(&deltas) else {
            out.mark_absent(
                self.id(),
                format!(
                    "column '{name}' is not a progressing time series (non-positive mean interval)"
                ),
            );
            return;
        };

        // Written `threshold > cv` (not `cv < threshold`) so the measure-zero
        // boundary mutant has a distinct `>`/`>=` descriptor — letting the
        // genuinely-killable `min_n` `<` above stay under the gate.
        if cfg.cad_max_cv > cv {
            // Lower CV ⇒ more metronomic ⇒ higher confidence.
            let confidence = (1.0 - cv / cfg.cad_max_cv).clamp(0.0, 1.0);
            out.push(Finding::new(
                self.id(),
                AnomalyClass::Cadence,
                Handle::Column { name: name.to_string() },
                confidence,
                cv,
                format!(
                    "column '{name}': inter-arrival CV={cv:.5} < {:.5} — metronomic (automated) cadence",
                    cfg.cad_max_cv
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{Column, RecordSet, Value};

    fn cfg_on(col: &str) -> DetectConfig {
        DetectConfig {
            cadence_column: Some(col.to_string()),
            ..DetectConfig::default()
        }
    }

    fn corpus(name: &str, values: &[f64]) -> RecordSet {
        RecordSet::new(
            "-",
            "t",
            vec![Column::new(
                name,
                values.iter().map(|&x| Value::Float(x)).collect(),
            )],
        )
    }

    fn run(rs: &RecordSet, cfg: &DetectConfig) -> Report {
        let mut out = Report::new();
        CadenceDetector.detect(&ScanContext::single(rs), cfg, &mut out);
        out
    }

    #[test]
    fn intervals_are_consecutive_differences() {
        assert_eq!(intervals(&[10.0, 12.0, 15.0, 19.0]), vec![2.0, 3.0, 4.0]);
        assert!(intervals(&[1.0]).is_empty());
    }

    #[test]
    fn cv_exact_and_guards() {
        // [2,4,6] mean 4, sample sd 2 ⇒ CV 0.5.
        assert!((coefficient_of_variation(&[2.0, 4.0, 6.0]).unwrap() - 0.5).abs() < 1e-12);
        // non-positive mean ⇒ undefined
        assert_eq!(coefficient_of_variation(&[-1.0, -2.0, -3.0]), None);
        assert_eq!(coefficient_of_variation(&[5.0]), None);
    }

    #[test]
    fn absent_without_a_cadence_column() {
        let ts: Vec<f64> = (0..30).map(|i| i as f64 * 60.0).collect();
        let report = run(&corpus("ts", &ts), &DetectConfig::default());
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
        assert_eq!(report.absent[0].detector, "cad.regularity");
    }

    #[test]
    fn metronomic_stream_is_flagged() {
        // Events exactly every 60 units → CV 0 → flagged with max confidence.
        let ts: Vec<f64> = (0..40).map(|i| 1_000_000.0 + i as f64 * 60.0).collect();
        let report = run(&corpus("ts", &ts), &cfg_on("ts"));
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(report.findings[0].handle, Handle::Column { .. }));
        assert_eq!(report.findings[0].class, AnomalyClass::Cadence);
        assert!(
            report.findings[0].confidence > 0.99,
            "CV≈0 ⇒ near-max confidence"
        );
    }

    #[test]
    fn jittery_human_stream_is_not_flagged() {
        // Irregular gaps (CV well above threshold) → no finding, but it ran.
        let gaps = [55.0, 71.0, 48.0, 90.0, 33.0, 62.0, 80.0, 41.0];
        let mut ts = vec![1_000_000.0];
        for i in 0..40 {
            ts.push(ts[i] + gaps[i % gaps.len()]);
        }
        let report = run(&corpus("ts", &ts), &cfg_on("ts"));
        assert!(
            report.findings.is_empty(),
            "ragged cadence is not anomalous"
        );
        assert!(report.absent.is_empty(), "it ran; not absent");
    }

    #[test]
    fn missing_column_is_absent() {
        let ts: Vec<f64> = (0..30).map(|i| i as f64 * 60.0).collect();
        let report = run(&corpus("ts", &ts), &cfg_on("nope"));
        assert_eq!(report.absent.len(), 1);
        assert!(report.absent[0].reason.contains("not found"));
    }

    #[test]
    fn runs_at_exactly_min_n_intervals() {
        // cad_min_n intervals = cad_min_n + 1 values; a metronomic series of
        // exactly that length must be assessed and flagged (pins the
        // `deltas.len() < min_n` boundary against `<=`).
        let n = DetectConfig::default().cad_min_n; // 20 intervals
        let ts: Vec<f64> = (0..=n).map(|i| 1_000_000.0 + i as f64 * 60.0).collect();
        let report = run(&corpus("ts", &ts), &cfg_on("ts"));
        assert_eq!(
            report.findings.len(),
            1,
            "exactly min_n intervals must be assessed"
        );
        assert!(report.absent.is_empty());
    }

    #[test]
    fn confidence_is_one_minus_cv_over_threshold() {
        // Alternating 100 / 100.1 gaps → a small but non-zero CV, well below the
        // 0.05 threshold. Pins confidence = 1 − cv/threshold exactly (the score
        // is the cv), catching the `/` → `*` / `%` mutations.
        let mut ts = vec![0.0];
        for i in 0..40 {
            ts.push(ts[i] + if i % 2 == 0 { 100.0 } else { 100.1 });
        }
        let report = run(&corpus("ts", &ts), &cfg_on("ts"));
        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert!(
            f.score > 0.0 && f.score < 0.05,
            "cv is small but positive: {}",
            f.score
        );
        let expected = 1.0 - f.score / DetectConfig::default().cad_max_cv;
        assert!((f.confidence - expected).abs() < 1e-12);
    }

    #[test]
    fn too_few_intervals_is_absent() {
        let ts: Vec<f64> = (0..10).map(|i| i as f64 * 60.0).collect();
        let report = run(&corpus("ts", &ts), &cfg_on("ts"));
        assert_eq!(report.absent.len(), 1);
        assert!(report.absent[0].reason.contains("intervals"));
    }

    #[test]
    fn confidence_increases_as_cadence_tightens() {
        // tighter (smaller-CV) cadence ⇒ higher confidence.
        let tight: Vec<f64> = (0..40)
            .map(|i| i as f64 * 100.0 + (i % 2) as f64 * 0.5)
            .collect();
        let tighter: Vec<f64> = (0..40)
            .map(|i| i as f64 * 100.0 + (i % 2) as f64 * 0.05)
            .collect();
        let c1 = run(&corpus("ts", &tight), &cfg_on("ts"));
        let c2 = run(&corpus("ts", &tighter), &cfg_on("ts"));
        assert_eq!(c1.findings.len(), 1);
        assert_eq!(c2.findings.len(), 1);
        assert!(c2.findings[0].confidence > c1.findings[0].confidence);
    }
}
