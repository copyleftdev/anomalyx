//! OpenTelemetry OTLP/JSON trace parser — the emerging default telemetry wire.
//!
//! An OTLP `ExportTraceServiceRequest` nests
//! `resourceSpans[].scopeSpans[].spans[]`. We flatten it to **one row per span**
//! and synthesize the columns the detectors want:
//!
//! - `durationNanos` = `endTimeUnixNano - startTimeUnixNano` → span-duration
//!   `point` outliers;
//! - `statusCode` → error-rate `dist` drift across a baseline;
//! - `startTimeUnixNano` → `--cadence` on emit intervals.
//!
//! Resource attributes (`resource.<key>`), scope (`scope.name`/`scope.version`),
//! and span attributes (the bare `<key>`) are flattened too, decoding the OTLP
//! `AnyValue` wrapper (`stringValue`/`intValue`/`doubleValue`/`boolValue`; arrays
//! and kvlists are kept as their canonical JSON string). OTLP/JSON encodes 64-bit
//! ints (times, `intValue`) as strings — we parse them back to `Int`.
//!
//! Claims `.otlp`; otherwise detected by the unmistakable top-level
//! `resourceSpans` array. (A `.json`-named dump routes to the generic JSON parser
//! by extension; pipe it on stdin to get OTLP-aware parsing.)

use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use serde_json::Value as J;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct OtlpParser;

/// Decodes an OTLP `AnyValue` wrapper object into a [`Value`].
fn decode_anyvalue(v: &J) -> Value {
    let Some(obj) = v.as_object() else {
        return Value::Null;
    };
    if let Some(s) = obj.get("stringValue").and_then(J::as_str) {
        return Value::Str(s.to_string());
    }
    if let Some(iv) = obj.get("intValue") {
        return match iv {
            // OTLP/JSON encodes int64 as a string; tolerate a bare number too.
            J::String(s) => s
                .parse::<i64>()
                .map_or_else(|_| Value::Str(s.clone()), Value::Int),
            J::Number(n) => n.as_i64().map_or(Value::Null, Value::Int),
            _ => Value::Null,
        };
    }
    if let Some(dv) = obj.get("doubleValue") {
        return dv
            .as_f64()
            .filter(|f| f.is_finite())
            .map_or(Value::Null, Value::Float);
    }
    if let Some(bv) = obj.get("boolValue") {
        return bv.as_bool().map_or(Value::Null, Value::Bool);
    }
    // arrayValue / kvlistValue / bytesValue: keep the canonical JSON, don't
    // explode into columns. An empty `{}` AnyValue is honest absence.
    for key in ["arrayValue", "kvlistValue", "bytesValue"] {
        if let Some(inner) = obj.get(key) {
            return Value::Str(inner.to_string());
        }
    }
    Value::Null
}

/// Flattens an OTLP attribute list (`[{key, value}]`) into `row`, key-prefixed.
fn collect_attributes(attrs: Option<&J>, prefix: &str, row: &mut BTreeMap<String, Value>) {
    for kv in attrs.and_then(J::as_array).into_iter().flatten() {
        if let (Some(k), Some(val)) = (kv.get("key").and_then(J::as_str), kv.get("value")) {
            row.insert(format!("{prefix}{k}"), decode_anyvalue(val));
        }
    }
}

/// Reads an OTLP unix-nano timestamp (string-encoded uint64, or a bare number).
fn unix_nano(v: Option<&J>) -> Option<i64> {
    match v? {
        J::String(s) => s.parse().ok(),
        J::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// Inserts a string span field as a column, if present.
fn insert_str(row: &mut BTreeMap<String, Value>, span: &J, field: &str, column: &str) {
    if let Some(s) = span.get(field).and_then(J::as_str) {
        row.insert(column.to_string(), Value::Str(s.to_string()));
    }
}

/// Adds the synthesized span columns. Called after attributes so the structural
/// fields win any (rare) collision with an attribute of the same name.
fn add_span_fields(span: &J, row: &mut BTreeMap<String, Value>) {
    insert_str(row, span, "traceId", "traceId");
    insert_str(row, span, "spanId", "spanId");
    insert_str(row, span, "name", "name");
    // A root span has an empty parentSpanId — record it as absent, not "".
    if let Some(p) = span.get("parentSpanId").and_then(J::as_str) {
        if !p.is_empty() {
            row.insert("parentSpanId".to_string(), Value::Str(p.to_string()));
        }
    }
    if let Some(kind) = span.get("kind").and_then(J::as_i64) {
        row.insert("kind".to_string(), Value::Int(kind));
    }
    let start = unix_nano(span.get("startTimeUnixNano"));
    let end = unix_nano(span.get("endTimeUnixNano"));
    if let Some(s) = start {
        row.insert("startTimeUnixNano".to_string(), Value::Int(s));
    }
    if let Some(e) = end {
        row.insert("endTimeUnixNano".to_string(), Value::Int(e));
    }
    // The headline metric: span duration. checked_sub guards a malformed pair.
    if let (Some(s), Some(e)) = (start, end) {
        if let Some(d) = e.checked_sub(s) {
            row.insert("durationNanos".to_string(), Value::Int(d));
        }
    }
    if let Some(status) = span.get("status") {
        if let Some(code) = status.get("code").and_then(J::as_i64) {
            row.insert("statusCode".to_string(), Value::Int(code));
        }
        insert_str(row, status, "message", "statusMessage");
    }
}

impl OtlpParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for OtlpParser {
    fn id(&self) -> &'static str {
        "otlp"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["otlp"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let value: J = serde_json::from_slice(bytes).ok()?;
        value
            .get("resourceSpans")
            .is_some_and(J::is_array)
            .then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let root: J = serde_json::from_slice(bytes).map_err(|e| self.err(e))?;
        let resource_spans = root
            .get("resourceSpans")
            .and_then(J::as_array)
            .ok_or_else(|| self.err("not OTLP traces: missing 'resourceSpans' array"))?;

        let mut builder = TableBuilder::new();
        for rs in resource_spans {
            let mut resource_row: BTreeMap<String, Value> = BTreeMap::new();
            if let Some(resource) = rs.get("resource") {
                collect_attributes(resource.get("attributes"), "resource.", &mut resource_row);
            }
            for ss in rs
                .get("scopeSpans")
                .and_then(J::as_array)
                .into_iter()
                .flatten()
            {
                let mut scope_row = resource_row.clone();
                if let Some(scope) = ss.get("scope") {
                    insert_str(&mut scope_row, scope, "name", "scope.name");
                    insert_str(&mut scope_row, scope, "version", "scope.version");
                }
                for span in ss.get("spans").and_then(J::as_array).into_iter().flatten() {
                    let mut row = scope_row.clone();
                    collect_attributes(span.get("attributes"), "", &mut row);
                    add_span_fields(span, &mut row);
                    builder.push_row(row);
                }
            }
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const TRACE: &str = r#"{
      "resourceSpans": [{
        "resource": {
          "attributes": [
            {"key": "service.name", "value": {"stringValue": "checkout"}}
          ]
        },
        "scopeSpans": [{
          "scope": {"name": "tracer", "version": "1.2.0"},
          "spans": [
            {
              "traceId": "5b8efff798038103d269b633813fc60c",
              "spanId": "eee19b7ec3c1b174",
              "name": "GET /cart",
              "kind": 2,
              "startTimeUnixNano": "1544712660000000000",
              "endTimeUnixNano": "1544712660500000000",
              "attributes": [
                {"key": "http.method", "value": {"stringValue": "GET"}},
                {"key": "http.status_code", "value": {"intValue": "200"}},
                {"key": "sampling.ratio", "value": {"doubleValue": 0.25}},
                {"key": "cache.hit", "value": {"boolValue": true}}
              ],
              "status": {"code": 1}
            },
            {
              "traceId": "5b8efff798038103d269b633813fc60c",
              "spanId": "f00d",
              "parentSpanId": "eee19b7ec3c1b174",
              "name": "db.query",
              "kind": 3,
              "startTimeUnixNano": "1544712660100000000",
              "endTimeUnixNano": "1544712660900000000",
              "status": {"code": 2, "message": "timeout"}
            }
          ]
        }]
      }]
    }"#;

    fn parse(s: &str) -> Vec<Column> {
        OtlpParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn one_row_per_span_with_duration() {
        let cols = parse(TRACE);
        let dur = col(&cols, "durationNanos");
        assert_eq!(dur.ty, ColType::Int);
        assert_eq!(dur.cells.len(), 2, "two spans");
        assert_eq!(dur.cells[0], Value::Int(500_000_000)); // 0.5s
        assert_eq!(dur.cells[1], Value::Int(800_000_000)); // 0.8s
    }

    #[test]
    fn synthesized_span_fields() {
        let cols = parse(TRACE);
        assert_eq!(
            col(&cols, "startTimeUnixNano").cells[0],
            Value::Int(1_544_712_660_000_000_000)
        );
        assert_eq!(col(&cols, "kind").cells[0], Value::Int(2));
        assert_eq!(col(&cols, "name").cells[1], Value::Str("db.query".into()));
        assert_eq!(col(&cols, "statusCode").cells[1], Value::Int(2));
        assert_eq!(
            col(&cols, "statusMessage").cells[1],
            Value::Str("timeout".into())
        );
    }

    #[test]
    fn parent_span_id_absent_on_root_present_on_child() {
        let cols = parse(TRACE);
        let parent = col(&cols, "parentSpanId");
        assert_eq!(parent.cells[0], Value::Null, "root span has no parent");
        assert_eq!(parent.cells[1], Value::Str("eee19b7ec3c1b174".into()));
    }

    #[test]
    fn resource_and_scope_attributes_flatten_onto_every_span() {
        let cols = parse(TRACE);
        let svc = col(&cols, "resource.service.name");
        assert_eq!(svc.cells[0], Value::Str("checkout".into()));
        assert_eq!(svc.cells[1], Value::Str("checkout".into()), "replicated");
        assert_eq!(
            col(&cols, "scope.name").cells[0],
            Value::Str("tracer".into())
        );
        assert_eq!(
            col(&cols, "scope.version").cells[0],
            Value::Str("1.2.0".into())
        );
    }

    #[test]
    fn any_value_decoding_per_type() {
        let cols = parse(TRACE);
        assert_eq!(col(&cols, "http.method").cells[0], Value::Str("GET".into()));
        assert_eq!(col(&cols, "http.status_code").cells[0], Value::Int(200)); // string int
        assert_eq!(col(&cols, "sampling.ratio").cells[0], Value::Float(0.25));
        assert_eq!(col(&cols, "cache.hit").cells[0], Value::Bool(true));
        // Span 2 has none of these attributes → null.
        assert_eq!(col(&cols, "http.method").cells[1], Value::Null);
    }

    #[test]
    fn decode_anyvalue_units() {
        assert_eq!(
            decode_anyvalue(&serde_json::json!({"intValue": 7})),
            Value::Int(7)
        ); // bare number
        assert_eq!(
            decode_anyvalue(&serde_json::json!({"arrayValue": {"values": []}})),
            Value::Str("{\"values\":[]}".into())
        );
        assert_eq!(decode_anyvalue(&serde_json::json!({})), Value::Null);
        assert_eq!(
            decode_anyvalue(&serde_json::json!("not an object")),
            Value::Null
        );
    }

    #[test]
    fn malformed_and_non_otlp_error() {
        // Not JSON at all.
        assert!(matches!(
            OtlpParser.parse("-", b"{not json"),
            Err(AxError::Parse { .. })
        ));
        // Valid JSON but not an OTLP trace export.
        assert!(matches!(
            OtlpParser.parse("-", br#"{"foo": 1}"#),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_resource_spans() {
        assert_eq!(OtlpParser.sniff(TRACE.as_bytes()), Some(STRONG));
        assert_eq!(OtlpParser.sniff(br#"{"resourceSpans": []}"#), Some(STRONG));
        // resourceSpans must be an array, not just any value.
        assert_eq!(OtlpParser.sniff(br#"{"resourceSpans": 1}"#), None);
        assert_eq!(OtlpParser.sniff(br#"{"resourceLogs": []}"#), None); // logs, not traces
        assert_eq!(OtlpParser.sniff(b"{\"a\":1}"), None);
        assert_eq!(OtlpParser.sniff(b"a,b,c\n1,2,3"), None); // not even JSON
    }

    #[test]
    fn unix_nano_accepts_string_and_number() {
        assert_eq!(unix_nano(Some(&serde_json::json!("123"))), Some(123)); // string-encoded
        assert_eq!(unix_nano(Some(&serde_json::json!(456))), Some(456)); // bare number
        assert_eq!(unix_nano(Some(&serde_json::json!(true))), None); // neither
        assert_eq!(unix_nano(None), None);
    }

    #[test]
    fn claims_otlp_extension() {
        assert_eq!(OtlpParser.extensions(), &["otlp"]);
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(
            reg.resolve("dump.otlp", TRACE.as_bytes()).unwrap().id(),
            "otlp"
        );
        // On stdin, the resourceSpans signature wins over the generic JSON sniff.
        assert_eq!(reg.resolve("-", TRACE.as_bytes()).unwrap().id(), "otlp");
    }
}
