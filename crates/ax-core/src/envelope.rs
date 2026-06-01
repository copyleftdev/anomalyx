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

/// Records output scoping (`--top` / `--min-severity`) when it is applied, so a
/// truncated finding list is never silently mistaken for the whole story. The
/// `summary`, `max_severity`, and `exit` always describe *everything detected*;
/// `rows` carries only the `emitted` subset, and this block says how many were
/// withheld and why.
#[derive(Debug, Clone, Serialize)]
pub struct Scope {
    /// Minimum severity retained, if `--min-severity` was set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// Cap on emitted findings, if `--top` was set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top: Option<usize>,
    /// Findings detected in total (before scoping).
    pub detected: usize,
    /// Findings emitted in `rows` (after scoping).
    pub emitted: usize,
    /// Findings withheld from `rows` (`detected − emitted`).
    pub dropped: usize,
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
    /// Source of the baseline corpus when scanning in compare mode; absent for
    /// a single-corpus scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
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
    /// Output scoping applied to `rows`, present only when `--top`/`--min-severity`
    /// withheld findings. Absent ⇒ `rows` is the complete detected set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// Committed exit code as an integer, mirrored into the envelope.
    pub exit: i32,
}

/// Assembles an [`Envelope`] from findings, interning strings deterministically.
pub struct EnvelopeBuilder {
    config_version: String,
    source: String,
    format: String,
    baseline: Option<String>,
    rows_scanned: usize,
    findings: Vec<Finding>,
    absent: Vec<Absence>,
    min_severity: Option<Severity>,
    top: Option<usize>,
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
            baseline: None,
            rows_scanned,
            findings: Vec::new(),
            absent: Vec::new(),
            min_severity: None,
            top: None,
        }
    }

    /// Restricts emitted findings to those at or above severity `s` (the full
    /// detected set still drives `summary`/`exit`). Output scoping, not detection.
    pub fn min_severity(mut self, s: Severity) -> Self {
        self.min_severity = Some(s);
        self
    }

    /// Caps emitted findings to the `n` most severe (findings are sorted
    /// severity-first, so this keeps the worst). Output scoping, not detection.
    pub fn top(mut self, n: usize) -> Self {
        self.top = Some(n);
        self
    }

    /// Records the baseline source for a compare-mode scan.
    pub fn baseline(mut self, source: impl Into<String>) -> Self {
        self.baseline = Some(source.into());
        self
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

        // `summary`, `max_severity`, and `exit` describe everything *detected*,
        // so output scoping can never make anomalies look absent (or flip the
        // exit code). Compute them before any scoping filter.
        let detected = self.findings.len();
        let max_severity = self.findings.iter().map(|f| f.severity).max();
        let by_class = AnomalyClass::ALL
            .iter()
            .map(|&class| ClassCount {
                class,
                count: self.findings.iter().filter(|f| f.class == class).count(),
            })
            .collect();
        let exit = if detected == 0 {
            ExitCode::Clean
        } else {
            ExitCode::Anomalies
        };

        // Apply output scoping to the (already severity-sorted) findings. The
        // most-severe survive `--top`; `--min-severity` keeps the floor and up.
        if let Some(min) = self.min_severity {
            self.findings.retain(|f| f.severity >= min);
        }
        if let Some(n) = self.top {
            self.findings.truncate(n);
        }
        let scope = if self.min_severity.is_some() || self.top.is_some() {
            Some(Scope {
                min_severity: self.min_severity,
                top: self.top,
                detected,
                emitted: self.findings.len(),
                dropped: detected - self.findings.len(),
            })
        } else {
            None
        };

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

        let summary = Summary {
            total: detected,
            max_severity,
            by_class,
        };

        Envelope {
            protocol: PROTOCOL.to_string(),
            config_version: self.config_version,
            source: self.source,
            format: self.format,
            baseline: self.baseline,
            rows_scanned: self.rows_scanned,
            dict,
            columns: FINDING_COLUMNS.iter().map(|s| s.to_string()).collect(),
            rows,
            absent: self.absent,
            summary,
            scope,
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
    fn exit_codes_are_committed() {
        assert_eq!(ExitCode::Clean.code(), 0);
        assert_eq!(ExitCode::Anomalies.code(), 1);
        assert_eq!(ExitCode::Error.code(), 2);
    }

    #[test]
    fn empty_is_clean() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 0).build();
        assert_eq!(env.exit, ExitCode::Clean.code());
        assert_eq!(env.summary.total, 0);
        assert_eq!(env.summary.max_severity, None);
    }

    #[test]
    fn by_class_counts_only_matching_class() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 3)
            .findings(vec![
                finding(0.9, AnomalyClass::Point, "a"),
                finding(0.9, AnomalyClass::Point, "b"),
                finding(0.9, AnomalyClass::Structural, "c"),
            ])
            .build();
        let count = |class: AnomalyClass| {
            env.summary
                .by_class
                .iter()
                .find(|cc| cc.class == class)
                .map(|cc| cc.count)
                .unwrap()
        };
        assert_eq!(count(AnomalyClass::Point), 2);
        assert_eq!(count(AnomalyClass::Structural), 1);
        assert_eq!(count(AnomalyClass::Cadence), 0);
    }

    #[test]
    fn no_scoping_omits_the_scope_block() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 2)
            .findings(vec![
                finding(0.9, AnomalyClass::Point, "a"),
                finding(0.5, AnomalyClass::Point, "b"),
            ])
            .build();
        assert!(env.scope.is_none(), "no scoping ⇒ no scope block");
        assert_eq!(env.summary.total, 2);
        assert_eq!(env.rows.len(), 2, "all findings emitted");
    }

    #[test]
    fn top_caps_emitted_but_summary_and_exit_reflect_all_detected() {
        // Three findings, keep the single most severe. summary/exit still report
        // the full detected reality; scope records the truncation.
        let env = EnvelopeBuilder::new("v", "-", "csv", 3)
            .findings(vec![
                finding(0.99, AnomalyClass::Point, "crit"), // Critical
                finding(0.50, AnomalyClass::Point, "lo1"),  // Low
                finding(0.50, AnomalyClass::Point, "lo2"),  // Low
            ])
            .top(1)
            .build();
        assert_eq!(env.rows.len(), 1, "only the top finding emitted");
        assert_eq!(env.summary.total, 3, "summary.total is the detected count");
        assert_eq!(env.exit, ExitCode::Anomalies.code());
        let scope = env.scope.unwrap();
        assert_eq!(scope.top, Some(1));
        assert_eq!((scope.detected, scope.emitted, scope.dropped), (3, 1, 2));
    }

    #[test]
    fn min_severity_filters_at_or_above_the_floor() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 3)
            .findings(vec![
                finding(0.99, AnomalyClass::Point, "crit"), // Critical
                finding(0.86, AnomalyClass::Point, "high"), // High
                finding(0.50, AnomalyClass::Point, "low"),  // Low
            ])
            .min_severity(Severity::High)
            .build();
        // Critical and High survive (>= High); Low is dropped.
        assert_eq!(env.rows.len(), 2);
        let scope = env.scope.unwrap();
        assert_eq!(scope.min_severity, Some(Severity::High));
        assert_eq!((scope.detected, scope.emitted, scope.dropped), (3, 2, 1));
    }

    #[test]
    fn scoping_to_zero_findings_still_exits_anomalies() {
        // The honesty guarantee: filtering every finding out of view must not
        // make anomalies look absent — exit stays 1 and the scope block shows
        // that 2 were detected and dropped.
        let env = EnvelopeBuilder::new("v", "-", "csv", 2)
            .findings(vec![
                finding(0.50, AnomalyClass::Point, "a"), // Low
                finding(0.50, AnomalyClass::Point, "b"), // Low
            ])
            .min_severity(Severity::Critical)
            .build();
        assert_eq!(env.rows.len(), 0, "nothing meets the critical floor");
        assert_eq!(
            env.exit,
            ExitCode::Anomalies.code(),
            "but anomalies WERE found"
        );
        assert_eq!(env.summary.total, 2);
        assert_eq!(env.summary.max_severity, Some(Severity::Low));
        let scope = env.scope.unwrap();
        assert_eq!((scope.detected, scope.emitted, scope.dropped), (2, 0, 2));
    }

    #[test]
    fn row_encodes_confidence_and_score_as_numbers() {
        let env = EnvelopeBuilder::new("v", "-", "csv", 1)
            .findings(vec![finding(0.77, AnomalyClass::Point, "a")])
            .build();
        // columns: [detector, class, handle, confidence, severity, score, reason]
        assert_eq!(env.rows[0][3].as_f64(), Some(0.77));
        assert_eq!(env.rows[0][5].as_f64(), Some(0.77));
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
