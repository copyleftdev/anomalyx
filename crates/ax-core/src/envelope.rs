//! The `tq1` output envelope — the wire contract.
//!
//! This is the article's "typed, dense output (not pretty text)": a versioned
//! JSON envelope with a dictionary-pinned string table, an explicit column
//! ordering for the dense finding rows, honest `absent` entries for detectors
//! that could not run, and a committed exit code. Changing any field here is an
//! API change and must break a contract test.

use crate::dict::Dict;
use crate::finding::{AnomalyClass, Finding, Severity};
use serde::Serialize;

/// Protocol identifier. Bump on any breaking change to the envelope shape.
pub const PROTOCOL: &str = "anomalyx/tq1";

/// Committed process exit codes. These are part of the contract: weakening them
/// must break a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// No anomalies found.
    Clean = 0,
    /// Anomalies found.
    Anomalies = 1,
    /// The tool could not complete (bad input, unresolved handle, …).
    Error = 2,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// A detector that declined to run, with a machine-readable reason. Recorded so
/// absence is *explicit* — an unavailable detector contributes nothing and says
/// so, rather than implying the data looked fine.
#[derive(Debug, Clone, Serialize)]
pub struct Absence {
    pub detector: String,
    pub reason: String,
}

/// The fixed column order of a dense finding row. Each row in
/// [`Envelope::rows`] is an array whose entries align to these names.
pub const FINDING_COLUMNS: [&str; 7] = [
    "detector",   // dict index
    "class",      // dict index
    "handle",     // dict index (canonical handle string)
    "confidence", // float
    "severity",   // dict index
    "score",      // float
    "reason",     // dict index
];

/// Per-class and overall counts, for the compact summary an agent reads first.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total: usize,
    pub max_severity: Option<Severity>,
    /// Counts keyed by class token, in [`AnomalyClass::ALL`] order.
    pub by_class: Vec<ClassCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassCount {
    pub class: AnomalyClass,
    pub count: usize,
}

/// The full envelope. Build it with [`EnvelopeBuilder`].
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    /// Protocol id, e.g. `"anomalyx/tq1"`.
    pub protocol: String,
    /// Config/version fingerprint. Same inputs + same fingerprint ⇒ same bytes.
    pub config_version: String,
    pub source: String,
    pub format: String,
    pub rows_scanned: usize,
    /// Dictionary-pinned string table; all `*_idx` values index into this.
    pub dict: Dict,
    /// Names for the dense row columns (always [`FINDING_COLUMNS`]).
    pub columns: Vec<String>,
    /// Dense finding rows — arrays aligned to `columns`.
    pub rows: Vec<Vec<serde_json::Value>>,
    /// Detectors that could not run (honest absence).
    pub absent: Vec<Absence>,
    pub summary: Summary,
    /// Committed exit code as an integer, mirrored into the envelope.
    pub exit: i32,
}

/// Assembles an [`Envelope`] from findings, interning strings deterministically.
pub struct EnvelopeBuilder {
    config_version: String,
    source: String,
    format: String,
    rows_scanned: usize,
    findings: Vec<Finding>,
    absent: Vec<Absence>,
}

impl EnvelopeBuilder {
    pub fn new(
        config_version: impl Into<String>,
        source: impl Into<String>,
        format: impl Into<String>,
        rows_scanned: usize,
    ) -> Self {
        EnvelopeBuilder {
            config_version: config_version.into(),
            source: source.into(),
            format: format.into(),
            rows_scanned,
            findings: Vec::new(),
            absent: Vec::new(),
        }
    }

    pub fn findings(mut self, mut findings: Vec<Finding>) -> Self {
        self.findings.append(&mut findings);
        self
    }

    pub fn absent(mut self, detector: impl Into<String>, reason: impl Into<String>) -> Self {
        self.absent.push(Absence {
            detector: detector.into(),
            reason: reason.into(),
        });
        self
    }

    /// Finalizes the envelope. Findings are sorted into a deterministic order
    /// (severity desc, then class, then handle, then detector) so the output is
    /// stable regardless of the order detectors ran or emitted in.
    pub fn build(mut self) -> Envelope {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.class.token().cmp(b.class.token()))
                .then_with(|| a.handle.canonical().cmp(&b.handle.canonical()))
                .then_with(|| a.detector.cmp(&b.detector))
        });

        let mut dict = Dict::new();
        let mut rows = Vec::with_capacity(self.findings.len());
        for f in &self.findings {
            let detector = dict.intern(&f.detector);
            let class = dict.intern(f.class.token());
            let handle = dict.intern(&f.handle.canonical());
            let severity = dict.intern(severity_token(f.severity));
            let reason = dict.intern(&f.reason);
            rows.push(vec![
                json_u32(detector),
                json_u32(class),
                json_u32(handle),
                json_f64(f.confidence),
                json_u32(severity),
                json_f64(f.score),
                json_u32(reason),
            ]);
        }

        let max_severity = self.findings.iter().map(|f| f.severity).max();
        let by_class = AnomalyClass::ALL
            .iter()
            .map(|&class| ClassCount {
                class,
                count: self.findings.iter().filter(|f| f.class == class).count(),
            })
            .collect();
        let summary = Summary {
            total: self.findings.len(),
            max_severity,
            by_class,
        };

        let exit = if self.findings.is_empty() {
            ExitCode::Clean
        } else {
            ExitCode::Anomalies
        };

        Envelope {
            protocol: PROTOCOL.to_string(),
            config_version: self.config_version,
            source: self.source,
            format: self.format,
            rows_scanned: self.rows_scanned,
            dict,
            columns: FINDING_COLUMNS.iter().map(|s| s.to_string()).collect(),
            rows,
            absent: self.absent,
            summary,
            exit: exit.code(),
        }
    }
}

fn severity_token(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn json_u32(v: u32) -> serde_json::Value {
    serde_json::Value::from(v)
}

fn json_f64(v: f64) -> serde_json::Value {
    serde_json::Number::from_f64(v)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Handle;

    fn finding(conf: f64, class: AnomalyClass, col: &str) -> Finding {
        Finding::new(
            "d",
            class,
            Handle::Column { name: col.into() },
            conf,
            conf,
            "r",
        )
    }

    #[test]
    fn empty_is_clean() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 0).build();
        assert_eq!(env.exit, ExitCode::Clean.code());
        assert_eq!(env.summary.total, 0);
        assert_eq!(env.summary.max_severity, None);
    }

    #[test]
    fn findings_set_anomalies_exit_and_max_severity() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 3)
            .findings(vec![
                finding(0.99, AnomalyClass::Point, "a"),
                finding(0.50, AnomalyClass::Structural, "b"),
            ])
            .build();
        assert_eq!(env.exit, ExitCode::Anomalies.code());
        assert_eq!(env.summary.total, 2);
        assert_eq!(env.summary.max_severity, Some(Severity::Critical));
        assert_eq!(env.columns.len(), FINDING_COLUMNS.len());
        // highest severity sorts first
        let first_sev_idx = env.rows[0][4].as_u64().unwrap() as u32;
        assert_eq!(env.dict.get(first_sev_idx), Some("critical"));
    }

    #[test]
    fn build_is_order_independent() {
        let a = EnvelopeBuilder::new("v", "-", "csv", 2)
            .findings(vec![
                finding(0.9, AnomalyClass::Point, "a"),
                finding(0.5, AnomalyClass::Point, "b"),
            ])
            .build();
        let b = EnvelopeBuilder::new("v", "-", "csv", 2)
            .findings(vec![
                finding(0.5, AnomalyClass::Point, "b"),
                finding(0.9, AnomalyClass::Point, "a"),
            ])
            .build();
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
