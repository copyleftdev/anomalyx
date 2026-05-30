//! # ax-detect — the detector engine
//!
//! A [`Detector`] is a contract: given a normalized [`RecordSet`], it either
//! *runs* and emits [`Finding`]s, or it declares honest [`Absence`] (e.g. "no
//! numeric columns"). It never fabricates a clean result for data it couldn't
//! assess. The [`Registry`] runs a set of detectors deterministically and
//! collects everything into one [`Report`], which the CLI turns into a `tq1`
//! envelope.
//!
//! All math routes through [`ax_core::det`], so every detector inherits
//! order-independent, reproducible reductions.

use ax_core::envelope::Absence;
use ax_core::{AnomalyClass, Finding, RecordSet};

pub mod config;
pub mod point;

pub use config::DetectConfig;
pub use point::PointDetector;

/// What a detector emits into the shared report. Detectors push findings and,
/// when they cannot meaningfully run, mark themselves absent with a reason.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub absent: Vec<Absence>,
}

impl Report {
    pub fn new() -> Self {
        Report::default()
    }

    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    /// Records that `detector` declined to run, with a machine-readable reason.
    pub fn mark_absent(&mut self, detector: &str, reason: impl Into<String>) {
        self.absent.push(Absence {
            detector: detector.to_string(),
            reason: reason.into(),
        });
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// A single anomaly-detection contract.
pub trait Detector {
    /// Stable, machine-readable identifier (appears in every finding).
    fn id(&self) -> &'static str;

    /// The taxonomy class this detector produces.
    fn class(&self) -> AnomalyClass;

    /// Assess `rs`, pushing findings and/or an absence into `out`.
    fn detect(&self, rs: &RecordSet, cfg: &DetectConfig, out: &mut Report);
}

/// An ordered set of detectors. Order is fixed at registration, so output is
/// deterministic; the envelope re-sorts findings, but absence order follows
/// registration for a stable contract.
pub struct Registry {
    detectors: Vec<Box<dyn Detector>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry { detectors: Vec::new() }
    }

    /// The default detector set for this protocol version.
    pub fn default_set() -> Self {
        let mut r = Registry::new();
        r.register(Box::new(PointDetector::default()));
        r
    }

    pub fn register(&mut self, d: Box<dyn Detector>) -> &mut Self {
        self.detectors.push(d);
        self
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.id()).collect()
    }

    /// Runs every detector against `rs` and returns the merged report.
    pub fn run(&self, rs: &RecordSet, cfg: &DetectConfig) -> Report {
        let mut out = Report::new();
        for d in &self.detectors {
            d.detect(rs, cfg, &mut out);
        }
        out
    }
}

impl Default for Registry {
    fn default() -> Self {
        Registry::default_set()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{Column, Value};

    #[test]
    fn registry_runs_registered_detectors() {
        let reg = Registry::default_set();
        assert_eq!(reg.ids(), vec!["point.modz"]);
        let rs = RecordSet::new(
            "-",
            "test",
            vec![Column::new("x", vec![Value::Int(1), Value::Int(2), Value::Int(3)])],
        );
        let report = reg.run(&rs, &DetectConfig::default());
        // a tight, normal column yields no point anomalies
        assert!(report.is_clean());
    }
}
