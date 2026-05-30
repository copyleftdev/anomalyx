//! The normalized scalar type. Every input format collapses into these cells.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// A single normalized cell value.
///
/// Arbitrary corpora (CSV, JSON, NDJSON, logs, Parquet, …) are reduced to a
/// columnar grid of these. The variant set is intentionally small: detectors
/// reason over a closed world, and "honest absence" is represented explicitly
/// by [`Value::Null`] rather than by a sentinel number or empty string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "lowercase")]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl Value {
    /// The column type this value contributes.
    pub fn col_type(&self) -> ColType {
        match self {
            Value::Null => ColType::Unknown,
            Value::Bool(_) => ColType::Bool,
            Value::Int(_) => ColType::Int,
            Value::Float(_) => ColType::Float,
            Value::Str(_) => ColType::Str,
        }
    }

    /// Numeric projection used by statistical detectors.
    ///
    /// `Int` and `Float` map to their `f64` value; `Bool` maps to `0.0`/`1.0`;
    /// `Null` and `Str` are non-numeric and return `None`. Honest absence: a
    /// `Null` never becomes a `0.0` that would skew a mean.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Null | Value::Str(_) => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Canonical string form, used for categorical/frequency detectors and as
    /// the basis for stable evidence handles.
    pub fn canonical(&self) -> String {
        match self {
            Value::Null => "\u{0}null".to_string(),
            Value::Bool(b) => format!("b:{b}"),
            Value::Int(i) => format!("i:{i}"),
            Value::Float(f) => format!("f:{:?}", f),
            Value::Str(s) => format!("s:{s}"),
        }
    }
}

/// A total order over values, so detector output (and thus the envelope) is
/// deterministic regardless of input ordering. Cross-variant ties break on a
/// fixed variant rank; floats use [`f64::total_cmp`] so NaN has a defined seat.
impl Value {
    pub fn total_cmp(&self, other: &Value) -> Ordering {
        fn rank(v: &Value) -> u8 {
            match v {
                Value::Null => 0,
                Value::Bool(_) => 1,
                Value::Int(_) => 2,
                Value::Float(_) => 3,
                Value::Str(_) => 4,
            }
        }
        match (self, other) {
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::Int(a), Value::Int(b)) => a.cmp(b),
            (Value::Float(a), Value::Float(b)) => a.total_cmp(b),
            (Value::Str(a), Value::Str(b)) => a.cmp(b),
            _ => rank(self).cmp(&rank(other)),
        }
    }
}

/// The inferred logical type of a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColType {
    /// No non-null value has been observed yet.
    Unknown,
    Bool,
    Int,
    Float,
    Str,
    /// Conflicting concrete types observed in the same column.
    Mixed,
}

impl ColType {
    /// Least-upper-bound when folding cell types into a column type.
    ///
    /// `Unknown` is the identity; `Int`+`Float` widen to `Float`; any other
    /// disagreement is `Mixed` (itself a structural anomaly signal, not an error).
    pub fn unify(self, other: ColType) -> ColType {
        use ColType::*;
        match (self, other) {
            (Unknown, x) | (x, Unknown) => x,
            (a, b) if a == b => a,
            (Int, Float) | (Float, Int) => Float,
            _ => Mixed,
        }
    }

    pub fn is_numeric(self) -> bool {
        matches!(self, ColType::Int | ColType::Float | ColType::Bool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_not_numeric_zero() {
        assert_eq!(Value::Null.as_f64(), None);
    }

    #[test]
    fn unify_widens_int_float() {
        assert_eq!(ColType::Int.unify(ColType::Float), ColType::Float);
        assert_eq!(ColType::Unknown.unify(ColType::Str), ColType::Str);
        assert_eq!(ColType::Bool.unify(ColType::Str), ColType::Mixed);
    }

    #[test]
    fn unify_is_commutative_and_idempotent() {
        let types = [
            ColType::Unknown,
            ColType::Bool,
            ColType::Int,
            ColType::Float,
            ColType::Str,
            ColType::Mixed,
        ];
        for &a in &types {
            assert_eq!(a.unify(a), a);
            for &b in &types {
                assert_eq!(a.unify(b), b.unify(a));
            }
        }
    }
}
