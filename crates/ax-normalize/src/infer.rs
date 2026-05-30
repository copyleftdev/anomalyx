//! Scalar type inference. Turns raw textual cells and JSON scalars into the
//! closed [`Value`] set, the same way regardless of which format they came from
//! — so a `1` in CSV and a `1` in JSON normalize identically.

use ax_core::Value;

/// Infers a [`Value`] from a raw textual cell (CSV/TSV).
///
/// Order matters: empty → `Null`; then integer, then float, then bool, else the
/// trimmed string. Quoting/whitespace handling is the CSV reader's job; this
/// sees the already-unquoted field.
pub fn infer_scalar(raw: &str) -> Value {
    if raw.is_empty() {
        return Value::Null;
    }
    if let Ok(i) = raw.parse::<i64>() {
        return Value::Int(i);
    }
    if let Ok(f) = raw.parse::<f64>() {
        // Reject the textual forms `inf`/`nan` that `f64::parse` accepts but
        // that are not meaningful data values; keep them as strings instead.
        if f.is_finite() {
            return Value::Float(f);
        }
    }
    match raw {
        "true" | "TRUE" | "True" => return Value::Bool(true),
        "false" | "FALSE" | "False" => return Value::Bool(false),
        _ => {}
    }
    Value::Str(raw.to_string())
}

/// Converts a JSON scalar to a [`Value`]. Nested objects/arrays are not
/// flattened here — they are preserved as their canonical JSON string and typed
/// as `Str`, so a structural detector can still see them without the normalizer
/// inventing a shape.
pub fn json_to_value(j: &serde_json::Value) -> Value {
    use serde_json::Value as J;
    match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() {
                    Value::Float(f)
                } else {
                    Value::Null
                }
            } else {
                // u64 too large for i64
                Value::Str(n.to_string())
            }
        }
        J::String(s) => Value::Str(s.clone()),
        J::Array(_) | J::Object(_) => Value::Str(j.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_inference_precedence() {
        assert!(matches!(infer_scalar(""), Value::Null));
        assert!(matches!(infer_scalar("42"), Value::Int(42)));
        assert!(matches!(infer_scalar("3.14"), Value::Float(_)));
        assert!(matches!(infer_scalar("true"), Value::Bool(true)));
        assert!(matches!(infer_scalar("false"), Value::Bool(false)));
        assert!(matches!(infer_scalar("False"), Value::Bool(false)));
        assert!(matches!(infer_scalar("hello"), Value::Str(_)));
        // textual inf/nan are NOT numeric values
        assert!(matches!(infer_scalar("inf"), Value::Str(_)));
        assert!(matches!(infer_scalar("nan"), Value::Str(_)));
    }

    #[test]
    fn json_scalar_conversion() {
        assert!(matches!(
            json_to_value(&serde_json::json!(null)),
            Value::Null
        ));
        assert!(matches!(
            json_to_value(&serde_json::json!(7)),
            Value::Int(7)
        ));
        assert!(matches!(
            json_to_value(&serde_json::json!(1.5)),
            Value::Float(_)
        ));
        assert!(matches!(
            json_to_value(&serde_json::json!(true)),
            Value::Bool(true)
        ));
        assert!(matches!(
            json_to_value(&serde_json::json!("s")),
            Value::Str(_)
        ));
        // nested preserved as canonical string
        assert!(matches!(
            json_to_value(&serde_json::json!({"k": 1})),
            Value::Str(_)
        ));
    }
}
