//! Column role classification — a deterministic, *transparent* read of what each
//! column is: a continuous `Measurement`, an `Identifier` (arbitrary label), a
//! low-cardinality `Categorical` code, a monotonic `Sequence`, or a `Constant`.
//!
//! Detectors consult the role to skip columns where their statistic is
//! meaningless — a "point outlier" in a process-id or a severity-code column is
//! noise, not signal. This is a heuristic, but never a *silent* one: every
//! column's role ships in the envelope (so an agent can see and audit it), and
//! the CLI's `--no-column-roles` disables role-based skipping entirely.
//!
//! Identifiers are recognized by **name** — the only reliable signal, since a
//! process-id column is statistically indistinguishable from a discrete
//! measurement. A continuous measurement (`fare`, `durationNanos`, `DAYS_LOST`)
//! is never named like an id, so it is never misclassified by this rule.

use crate::record::Column;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A strictly-monotonic numeric column of at least this length is a sequence
/// (a counter/timestamp ramp). Short columns don't carry enough evidence — and
/// a near-constant column with a couple of outliers is *not* a sequence.
const SEQUENCE_MIN_LEN: usize = 20;

/// Name tokens that mark a column as an identifier (matched case-insensitively
/// against the column name split on non-alphanumerics and camelCase).
const ID_TOKENS: &[&str] = &[
    "id",
    "ids",
    "uid",
    "uuid",
    "guid",
    "gid",
    "pid",
    "procid",
    "ppid",
    "tid",
    "sid",
    "session",
    "sessionid",
];

/// What a column appears to be. Only [`Role::Measurement`] columns are subject to
/// magnitude-outlier (point) detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Continuous numeric measurement — outlier detection is meaningful.
    Measurement,
    /// An arbitrary label (process id, uuid, foreign key); magnitude is meaningless.
    Identifier,
    /// A low-cardinality code / enum / flag.
    Categorical,
    /// A strictly monotonic sequence (timestamp, counter, auto-increment id).
    Sequence,
    /// A single value, or none.
    Constant,
}

impl Role {
    pub fn token(self) -> &'static str {
        match self {
            Role::Measurement => "measurement",
            Role::Identifier => "identifier",
            Role::Categorical => "categorical",
            Role::Sequence => "sequence",
            Role::Constant => "constant",
        }
    }

    /// Whether magnitude-outlier (point) detection is meaningful for this role.
    pub fn is_measured(self) -> bool {
        matches!(self, Role::Measurement)
    }

    /// Whether a *value-distribution* detector (point, contextual, collective,
    /// distributional, multivariate) should skip a column of this role: an
    /// `Identifier` is an arbitrary label and a `Sequence` is a monotonic ramp,
    /// so any value-based anomaly statistic on them is noise, not signal. A
    /// `Constant` is left to each detector (it naturally produces nothing), and a
    /// `Categorical` is the chi-square detector's legitimate input.
    pub fn skips_value_detection(self) -> bool {
        matches!(self, Role::Identifier | Role::Sequence)
    }
}

/// A column name paired with its classified role, for the envelope.
#[derive(Debug, Clone, Serialize)]
pub struct ColumnRole {
    pub column: String,
    pub role: Role,
}

/// Lowercased name tokens, split on non-alphanumerics and camelCase boundaries:
/// `"SYSLOG_PID"` → `[syslog, pid]`, `"durationNanos"` → `[duration, nanos]`.
fn name_tokens(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower_or_digit = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() && prev_lower_or_digit && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur.push(ch.to_ascii_lowercase());
            prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower_or_digit = false;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether a column name reads as an identifier (any token in [`ID_TOKENS`]).
pub fn name_is_identifier(name: &str) -> bool {
    name_tokens(name)
        .iter()
        .any(|t| ID_TOKENS.contains(&t.as_str()))
}

/// Name tokens marking a clock/time column. A timestamp is a monotonic-ish clock
/// value, never a measurement to outlier-test — and real timestamps (journald's
/// `__REALTIME_TIMESTAMP`, a pcap `timestamp`) tie/regress just often enough to
/// fail strict-monotonic [`Role::Sequence`] detection, so we also catch them by
/// name. Kept narrow (`timestamp`/`ts`) to avoid `response_time`-style
/// measurements you *do* want outliers on.
const TIME_TOKENS: &[&str] = &["timestamp", "ts"];

/// Whether a column name reads as a timestamp/clock column.
pub fn name_is_timestamp(name: &str) -> bool {
    name_tokens(name)
        .iter()
        .any(|t| TIME_TOKENS.contains(&t.as_str()))
}

/// A stable per-value key for distinct counting (NaN-safe via bit pattern).
fn distinct_key(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => format!("b{b}"),
        Value::Int(i) => format!("i{i}"),
        Value::Float(f) => format!("f{}", f.to_bits()),
        Value::Str(s) => format!("s{s}"),
    }
}

fn is_strictly_monotonic(xs: &[f64]) -> bool {
    if xs.len() < 2 {
        return false;
    }
    let increasing = xs.windows(2).all(|w| w[1] > w[0]);
    let decreasing = xs.windows(2).all(|w| w[1] < w[0]);
    increasing || decreasing
}

impl Column {
    /// Number of distinct non-null values in this column.
    fn distinct_count(&self) -> usize {
        let mut seen = BTreeSet::new();
        for c in &self.cells {
            if !matches!(c, Value::Null) {
                seen.insert(distinct_key(c));
            }
        }
        seen.len()
    }

    /// Classifies this column's [`Role`]. Deterministic; order of checks matters:
    /// constant first, then identifier (by name), then — for numeric columns — a
    /// monotonic sequence else a continuous measurement; non-numeric columns that
    /// are none of the above are categorical (labels/codes/free text).
    ///
    /// Cardinality is deliberately *not* used to call a numeric column
    /// "categorical": a column that is one value with a few wild outliers has low
    /// cardinality yet is exactly what point detection should catch. Identifiers
    /// are caught by name, not by how many distinct values they hold.
    pub fn role(&self) -> Role {
        if self.distinct_count() <= 1 {
            return Role::Constant;
        }
        if name_is_identifier(&self.name) {
            return Role::Identifier;
        }
        // A clock column is a sequence regardless of type or exact monotonicity.
        if name_is_timestamp(&self.name) {
            return Role::Sequence;
        }
        if self.ty.is_numeric() {
            let xs = self.numeric();
            if xs.len() >= SEQUENCE_MIN_LEN && is_strictly_monotonic(&xs) {
                Role::Sequence
            } else {
                Role::Measurement
            }
        } else {
            Role::Categorical
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, cells: Vec<Value>) -> Column {
        Column::new(name, cells)
    }

    fn ints(name: &str, xs: &[i64]) -> Column {
        col(name, xs.iter().map(|&i| Value::Int(i)).collect())
    }

    #[test]
    fn role_tokens_and_is_measured() {
        assert_eq!(Role::Measurement.token(), "measurement");
        assert_eq!(Role::Identifier.token(), "identifier");
        assert_eq!(Role::Categorical.token(), "categorical");
        assert_eq!(Role::Sequence.token(), "sequence");
        assert_eq!(Role::Constant.token(), "constant");
        // Only a measurement is subject to magnitude-outlier detection.
        assert!(Role::Measurement.is_measured());
        for r in [
            Role::Identifier,
            Role::Categorical,
            Role::Sequence,
            Role::Constant,
        ] {
            assert!(!r.is_measured(), "{:?} must not be measured", r);
        }
    }

    #[test]
    fn skips_value_detection_targets_identifier_and_sequence() {
        assert!(Role::Identifier.skips_value_detection());
        assert!(Role::Sequence.skips_value_detection());
        // Measurement is analyzed; Categorical feeds chi-square; Constant is
        // left to each detector to no-op — none are skipped by this gate.
        for r in [Role::Measurement, Role::Categorical, Role::Constant] {
            assert!(!r.skips_value_detection(), "{:?} must not be skipped", r);
        }
    }

    #[test]
    fn strictly_monotonic_predicate() {
        assert!(is_strictly_monotonic(&[1.0, 2.0, 3.0])); // increasing
        assert!(is_strictly_monotonic(&[3.0, 2.0, 1.0])); // decreasing
        assert!(is_strictly_monotonic(&[1.0, 2.0])); // len 2 still decides (pins the len guard)
        assert!(!is_strictly_monotonic(&[1.0, 1.0, 2.0])); // not strict (equal step up)
        assert!(!is_strictly_monotonic(&[3.0, 3.0, 1.0])); // not strict (equal step down)
        assert!(!is_strictly_monotonic(&[1.0, 3.0, 2.0])); // up then down
        assert!(!is_strictly_monotonic(&[5.0])); // too short
        assert!(!is_strictly_monotonic(&[])); // empty
    }

    #[test]
    fn name_tokenizer_splits_underscores_and_camel_case() {
        assert_eq!(name_tokens("SYSLOG_PID"), vec!["syslog", "pid"]);
        assert_eq!(name_tokens("durationNanos"), vec!["duration", "nanos"]);
        assert_eq!(name_tokens("sessionId"), vec!["session", "id"]);
        assert_eq!(name_tokens("_PID"), vec!["pid"]);
        assert_eq!(name_tokens("JOB_ID"), vec!["job", "id"]);
    }

    #[test]
    fn identifier_names_recognized_without_false_positives() {
        for id in [
            "_PID",
            "_UID",
            "_GID",
            "JOB_ID",
            "TID",
            "SYSLOG_PID",
            "user_id",
            "uuid",
            "procid",
        ] {
            assert!(
                name_is_identifier(id),
                "{id} should look like an identifier"
            );
        }
        // Continuous measurements are never named like ids — no false positives.
        for m in [
            "DAYS_LOST",
            "durationNanos",
            "fare",
            "age",
            "humidity",
            "valid",
            "period",
        ] {
            assert!(
                !name_is_identifier(m),
                "{m} must NOT look like an identifier"
            );
        }
    }

    #[test]
    fn timestamp_named_columns_are_sequences() {
        // journald's near-monotonic clocks tie/regress, so strict-monotonic
        // detection misses them; the name catches them. Numeric or not.
        for ts in [
            "__REALTIME_TIMESTAMP",
            "__MONOTONIC_TIMESTAMP",
            "timestamp",
            "ts",
        ] {
            assert!(name_is_timestamp(ts), "{ts} should read as a timestamp");
            // a jittery (non-strictly-monotonic) clock column → Sequence by name
            let jittery = ints(ts, &[100, 101, 101, 105, 104, 110, 130]);
            assert_eq!(jittery.role(), Role::Sequence, "{ts}");
        }
        // but a real measurement whose name merely contains "time" is NOT a
        // timestamp — we still want outliers on it.
        for m in ["response_time", "DAYS_LOST", "duration_ms", "fare"] {
            assert!(!name_is_timestamp(m), "{m} must NOT read as a timestamp");
        }
    }

    #[test]
    fn constant_takes_precedence() {
        assert_eq!(ints("anything", &[5, 5, 5, 5]).role(), Role::Constant);
        // Even an id-named single-value column is Constant (distinct <= 1 first).
        assert_eq!(ints("user_id", &[7, 7]).role(), Role::Constant);
    }

    #[test]
    fn identifier_by_name_beats_a_numeric_distribution() {
        // A process-id column is mid-cardinality with repeats — statistically a
        // discrete measurement, but its name gives it away.
        let pid = ints("_PID", &[100, 200, 100, 300, 200, 100, 400, 300, 100]);
        assert_eq!(pid.role(), Role::Identifier);
    }

    #[test]
    fn long_strictly_monotonic_numeric_is_a_sequence() {
        let up: Vec<i64> = (0..40).collect();
        assert_eq!(ints("ts", &up).role(), Role::Sequence);
        let down: Vec<i64> = (0..40).rev().collect();
        assert_eq!(ints("countdown", &down).role(), Role::Sequence);
        // A short monotonic run is NOT enough evidence (below SEQUENCE_MIN_LEN).
        assert_eq!(
            ints("small", &[10, 11, 14, 20, 31]).role(),
            Role::Measurement
        );
    }

    #[test]
    fn near_constant_with_outliers_stays_measurement_not_categorical() {
        // Low cardinality (2 distinct), but this is the canonical point-outlier
        // shape — it must remain a measurement, never be skipped as a category.
        let mut xs = vec![10i64; 30];
        xs.push(1000);
        assert_eq!(ints("x", &xs).role(), Role::Measurement);
    }

    #[test]
    fn non_numeric_default_is_categorical() {
        let msg = col(
            "message",
            (0..50).map(|i| Value::Str(format!("event {i}"))).collect(),
        );
        assert_eq!(msg.role(), Role::Categorical);
        // A constant string column is still Constant (distinct <= 1 wins).
        let same = col("kind", vec![Value::Str("a".into()); 5]);
        assert_eq!(same.role(), Role::Constant);
    }
}
