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

pub mod cadence;
pub mod calibrate;
pub mod coll;
pub mod config;
pub mod ctx;
pub mod dist;
pub mod fdr;
pub mod linalg;
pub mod mv;
pub mod point;
pub mod robustz;
pub mod structural;

pub use cadence::CadenceDetector;
pub use coll::CusumDetector;
pub use config::DetectConfig;
pub use ctx::SeasonalDetector;
pub use dist::{Chi2Detector, KsDetector, PsiDetector};
pub use mv::MahalanobisDetector;
pub use point::PointDetector;
pub use structural::SchemaDetector;

/// The corpus (or pair of corpora) under assessment.
///
/// Single-corpus detectors (point, structural shape checks) read `current`.
/// Drift detectors (distributional, schema-diff) require `baseline`; when it is
/// `None` they declare honest [`Absence`] rather than inventing a comparison.
#[derive(Debug, Clone, Copy)]
pub struct ScanContext<'a> {
    pub current: &'a RecordSet,
    pub baseline: Option<&'a RecordSet>,
}

impl<'a> ScanContext<'a> {
    /// A single-corpus context (no baseline).
    pub fn single(current: &'a RecordSet) -> Self {
        ScanContext {
            current,
            baseline: None,
        }
    }

    /// A baseline-vs-current context.
    pub fn compared(baseline: &'a RecordSet, current: &'a RecordSet) -> Self {
        ScanContext {
            current,
            baseline: Some(baseline),
        }
    }
}

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

    /// Assess `ctx`, pushing findings and/or an absence into `out`.
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report);
}

/// An ordered set of detectors. Order is fixed at registration, so output is
/// deterministic; the envelope re-sorts findings, but absence order follows
/// registration for a stable contract.
pub struct Registry {
    detectors: Vec<Box<dyn Detector>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            detectors: Vec::new(),
        }
    }

    /// The default detector set for this protocol version. Single-corpus
    /// detectors run always; drift detectors run when a baseline is present and
    /// otherwise report honest absence.
    pub fn default_set() -> Self {
        let mut r = Registry::new();
        r.register(Box::new(PointDetector));
        r.register(Box::new(SchemaDetector));
        r.register(Box::new(KsDetector));
        r.register(Box::new(PsiDetector));
        r.register(Box::new(Chi2Detector));
        r.register(Box::new(MahalanobisDetector));
        r.register(Box::new(SeasonalDetector));
        r.register(Box::new(CusumDetector));
        r.register(Box::new(CadenceDetector));
        r
    }

    pub fn register(&mut self, d: Box<dyn Detector>) -> &mut Self {
        self.detectors.push(d);
        self
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.id()).collect()
    }

    /// Runs every detector against `ctx` and returns the merged report.
    pub fn run(&self, ctx: &ScanContext, cfg: &DetectConfig) -> Report {
        let mut out = Report::new();
        for d in &self.detectors {
            d.detect(ctx, cfg, &mut out);
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
    fn report_is_clean_only_without_findings() {
        let mut r = Report::new();
        assert!(r.is_clean());
        r.push(Finding::new(
            "d",
            AnomalyClass::Point,
            ax_core::Handle::Column { name: "x".into() },
            0.9,
            1.0,
            "r",
        ));
        assert!(!r.is_clean());
    }

    #[test]
    fn registry_registers_the_default_detector_set() {
        let reg = Registry::default_set();
        assert_eq!(
            reg.ids(),
            vec![
                "point.modz",
                "struct.schema",
                "dist.ks",
                "dist.psi",
                "dist.chi2",
                "mv.mahalanobis",
                "ctx.seasonal",
                "coll.cusum",
                "cad.regularity"
            ]
        );
    }

    #[test]
    fn single_corpus_clean_numeric_has_no_point_findings() {
        let rs = RecordSet::new(
            "-",
            "test",
            vec![Column::new(
                "x",
                (0..12).map(|i| Value::Int(10 + i % 3)).collect(),
            )],
        );
        let report =
            Registry::default_set().run(&ScanContext::single(&rs), &DetectConfig::default());
        // point detector finds nothing; drift detectors are honestly absent
        assert!(report.findings.is_empty());
        assert!(report.absent.iter().any(|a| a.detector == "dist.ks"));
    }

    #[test]
    fn registry_run_surfaces_point_finding() {
        let mut cells: Vec<Value> = (0..12).map(|i| Value::Int(10 + i % 3)).collect();
        cells.push(Value::Int(100_000)); // unmistakable outlier
        let rs = RecordSet::new("-", "test", vec![Column::new("x", cells)]);
        let report =
            Registry::default_set().run(&ScanContext::single(&rs), &DetectConfig::default());
        assert!(report.findings.iter().any(|f| f.detector == "point.modz"));
    }
}
