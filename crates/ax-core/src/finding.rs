//! The anomaly taxonomy, findings, and evidence handles.
//!
//! No Rust crate ships a coherent *taxonomy* of anomaly kinds wired to an
//! explainable, ensembled output — that classification is the product. Every
//! detector, whatever math it runs, lands its output in one [`AnomalyClass`]
//! and emits [`Finding`]s carrying a stable [`Handle`] for `explain` to resolve.

use crate::value::ColType;
use serde::{Deserialize, Serialize};

/// The top-level anomaly taxonomy. A detector declares which class it produces;
/// the CLI groups and reports findings by class so an agent can reason about
/// *kind* of deviation, not just "something is off."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyClass {
    /// A single value far from its column's distribution (z-score, MAD, IQR, ESD).
    Point,
    /// A value anomalous only in context (seasonal/time-of-day deviation).
    Contextual,
    /// A subsequence or group that is jointly anomalous (change-point, runs).
    Collective,
    /// The distribution itself shifted vs. a baseline (KS, PSI, KL, chi²).
    Distributional,
    /// Schema/type/shape violation (type drift, missing field, cardinality blowup).
    Structural,
    /// A multivariate point isolated in feature space (isolation forest, LOF, DBSCAN).
    Multivariate,
    /// Suspiciously regular timing (metronomic cadence).
    Cadence,
}

impl AnomalyClass {
    /// Stable machine token, also used as the dictionary key in the envelope.
    pub fn token(self) -> &'static str {
        match self {
            AnomalyClass::Point => "point",
            AnomalyClass::Contextual => "contextual",
            AnomalyClass::Collective => "collective",
            AnomalyClass::Distributional => "distributional",
            AnomalyClass::Structural => "structural",
            AnomalyClass::Multivariate => "multivariate",
            AnomalyClass::Cadence => "cadence",
        }
    }

    /// Every class, in stable order — the basis for `describe` output and for
    /// deterministic grouping.
    pub const ALL: [AnomalyClass; 7] = [
        AnomalyClass::Point,
        AnomalyClass::Contextual,
        AnomalyClass::Collective,
        AnomalyClass::Distributional,
        AnomalyClass::Structural,
        AnomalyClass::Multivariate,
        AnomalyClass::Cadence,
    ];
}

/// Severity buckets derived from confidence, used for the process exit code and
/// for at-a-glance triage. Ordered so `max` is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Maps a calibrated confidence in `[0, 1]` to a severity bucket.
    pub fn from_confidence(c: f64) -> Severity {
        match c {
            c if c >= 0.95 => Severity::Critical,
            c if c >= 0.85 => Severity::High,
            c if c >= 0.65 => Severity::Medium,
            c if c >= 0.40 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

/// A stable, drill-able pointer to the evidence behind a finding.
///
/// Handles are the article's "handle-based evidence navigation": the `scan`
/// summary stays compact, and `explain <handle>` resolves one back to the
/// underlying record/column/cell. Their string form is canonical and stable
/// across runs so an agent can cache and re-query them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Handle {
    /// A whole column, by name.
    Column { name: String },
    /// A single cell at `(column, row)`.
    Cell { column: String, row: usize },
    /// A contiguous row range `[start, end)` within a column.
    Range {
        column: String,
        start: usize,
        end: usize,
    },
    /// A distribution-level finding comparing `column` against a baseline.
    Dist { column: String },
}

impl Handle {
    /// Canonical wire form, e.g. `cell:amount:42` or `col:status`.
    pub fn canonical(&self) -> String {
        match self {
            Handle::Column { name } => format!("col:{name}"),
            Handle::Cell { column, row } => format!("cell:{column}:{row}"),
            Handle::Range { column, start, end } => format!("range:{column}:{start}:{end}"),
            Handle::Dist { column } => format!("dist:{column}"),
        }
    }

    /// Parses the canonical form. Returns `None` on any malformed handle so the
    /// CLI can fail cleanly rather than guess (honest absence).
    pub fn parse(s: &str) -> Option<Handle> {
        let (kind, rest) = s.split_once(':')?;
        match kind {
            "col" => Some(Handle::Column { name: rest.to_string() }),
            "dist" => Some(Handle::Dist { column: rest.to_string() }),
            "cell" => {
                let (column, row) = rest.rsplit_once(':')?;
                Some(Handle::Cell {
                    column: column.to_string(),
                    row: row.parse().ok()?,
                })
            }
            "range" => {
                let mut it = rest.rsplitn(3, ':');
                let end = it.next()?.parse().ok()?;
                let start = it.next()?.parse().ok()?;
                let column = it.next()?.to_string();
                Some(Handle::Range { column, start, end })
            }
            _ => None,
        }
    }
}

/// One detected anomaly with everything an agent needs to act or drill in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Detector that produced this finding (stable id).
    pub detector: String,
    pub class: AnomalyClass,
    pub handle: Handle,
    /// Calibrated confidence in `[0, 1]`.
    pub confidence: f64,
    pub severity: Severity,
    /// Raw detector score, before calibration (e.g. a z-score). Interpretation
    /// is detector-specific; kept for evidence, not comparison across detectors.
    pub score: f64,
    /// Short, human/agent-readable reason. No prose padding.
    pub reason: String,
    /// Optional column type context, for structural findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col_type: Option<ColType>,
}

impl Finding {
    /// Builds a finding, deriving severity from `confidence`.
    pub fn new(
        detector: impl Into<String>,
        class: AnomalyClass,
        handle: Handle,
        confidence: f64,
        score: f64,
        reason: impl Into<String>,
    ) -> Self {
        let confidence = confidence.clamp(0.0, 1.0);
        Finding {
            detector: detector.into(),
            class,
            handle,
            confidence,
            severity: Severity::from_confidence(confidence),
            score,
            reason: reason.into(),
            col_type: None,
        }
    }

    pub fn with_col_type(mut self, ty: ColType) -> Self {
        self.col_type = Some(ty);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_roundtrips() {
        let cases = [
            Handle::Column { name: "status".into() },
            Handle::Cell { column: "amount".into(), row: 42 },
            Handle::Range { column: "ts".into(), start: 3, end: 9 },
            Handle::Dist { column: "score".into() },
        ];
        for h in cases {
            let s = h.canonical();
            assert_eq!(Handle::parse(&s), Some(h), "roundtrip failed for {s}");
        }
    }

    #[test]
    fn handle_rejects_garbage() {
        assert_eq!(Handle::parse("nope"), None);
        assert_eq!(Handle::parse("cell:amount:notanumber"), None);
    }

    #[test]
    fn class_tokens_are_exact() {
        assert_eq!(AnomalyClass::Point.token(), "point");
        assert_eq!(AnomalyClass::Distributional.token(), "distributional");
        assert_eq!(AnomalyClass::Cadence.token(), "cadence");
        // every class has a distinct, non-empty token
        let mut seen = std::collections::HashSet::new();
        for c in AnomalyClass::ALL {
            assert!(!c.token().is_empty());
            assert!(seen.insert(c.token()), "duplicate token {}", c.token());
        }
    }

    #[test]
    fn severity_buckets_are_exact_at_boundaries() {
        let cases = [
            (0.96, Severity::Critical),
            (0.95, Severity::Critical),
            (0.90, Severity::High),
            (0.85, Severity::High),
            (0.70, Severity::Medium),
            (0.65, Severity::Medium),
            (0.50, Severity::Low),
            (0.40, Severity::Low),
            (0.30, Severity::Info),
            (0.0, Severity::Info),
        ];
        for (c, want) in cases {
            assert_eq!(Severity::from_confidence(c), want, "confidence {c}");
        }
    }

    #[test]
    fn severity_is_monotonic_in_confidence() {
        let mut prev = Severity::Info;
        for c in [0.0, 0.4, 0.65, 0.85, 0.95, 1.0] {
            let s = Severity::from_confidence(c);
            assert!(s >= prev);
            prev = s;
        }
    }

    #[test]
    fn confidence_is_clamped() {
        let f = Finding::new("d", AnomalyClass::Point, Handle::Column { name: "x".into() }, 5.0, 9.0, "r");
        assert_eq!(f.confidence, 1.0);
        assert_eq!(f.severity, Severity::Critical);
    }
}
