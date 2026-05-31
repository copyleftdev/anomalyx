//! Suricata/Zeek EVE JSON parser — the standard IDS alert stream.
//!
//! EVE is NDJSON (one event per line), every event tagged with an `event_type`
//! (`alert`, `dns`, `flow`, `http`, …) and a `timestamp`. The interesting fields
//! live one level down in a per-type object (`alert.signature`, `alert.category`,
//! `alert.severity`, `dns.rrname`, …). Generic NDJSON would stringify those
//! nested objects; this parser **flattens them into dotted columns** so a value
//! like `alert.category` is its own column — exactly what `dist.chi2 --baseline`
//! reads as alert-type drift (quiet vs incident window), with a brand-new alert
//! class surfacing as a category never seen in the baseline.
//!
//! Arrays are kept as their canonical JSON string (not exploded). Detected by the
//! `event_type` + `timestamp` signature; claims no extension (EVE is generically
//! `eve.json`, owned by the JSON parser — pipe it on stdin for EVE-aware
//! flattening).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use serde_json::Value as J;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct EveParser;

fn looks_like_eve(obj: &serde_json::Map<String, J>) -> bool {
    obj.get("event_type").is_some_and(J::is_string) && obj.contains_key("timestamp")
}

/// Flattens nested objects into dotted keys (`alert.category`); scalars and
/// arrays are leaves (arrays kept as canonical JSON via [`infer::json_to_value`]).
fn flatten(prefix: &str, value: &J, row: &mut BTreeMap<String, Value>) {
    match value {
        J::Object(map) => {
            for (key, val) in map {
                let dotted = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&dotted, val, row);
            }
        }
        leaf => {
            row.insert(prefix.to_string(), infer::json_to_value(leaf));
        }
    }
}

impl EveParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for EveParser {
    fn id(&self) -> &'static str {
        "eve"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        let value: J = serde_json::from_str(line).ok()?;
        value
            .as_object()
            .is_some_and(looks_like_eve)
            .then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: J = serde_json::from_str(line).map_err(|e| self.err(e))?;
            if !value.is_object() {
                return Err(self.err("EVE event is not a JSON object"));
            }
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            flatten("", &value, &mut row);
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const EVE: &str = concat!(
        r#"{"timestamp":"2017-01-01T00:00:01.0+0000","flow_id":12,"event_type":"alert","src_ip":"1.2.3.4","src_port":1234,"dest_ip":"5.6.7.8","dest_port":80,"proto":"TCP","alert":{"signature_id":2010935,"signature":"ET POLICY external IP","category":"Potential Corporate Privacy Violation","severity":1},"metadata":["a","b"]}"#,
        "\n",
        r#"{"timestamp":"2017-01-01T00:00:02.0+0000","flow_id":13,"event_type":"dns","src_ip":"1.2.3.4","proto":"UDP","dns":{"type":"query","rrname":"example.com"}}"#,
        "\n",
    );

    fn parse(s: &str) -> Vec<Column> {
        EveParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn top_level_fields_are_typed() {
        let cols = parse(EVE);
        assert_eq!(
            col(&cols, "event_type").cells[0],
            Value::Str("alert".into())
        );
        assert_eq!(col(&cols, "src_port").ty, ColType::Int);
        assert_eq!(col(&cols, "src_port").cells[0], Value::Int(1234));
        assert_eq!(col(&cols, "dest_ip").cells[0], Value::Str("5.6.7.8".into()));
        assert_eq!(col(&cols, "flow_id").cells[1], Value::Int(13));
    }

    #[test]
    fn nested_alert_object_is_flattened_to_dotted_columns() {
        let cols = parse(EVE);
        assert_eq!(
            col(&cols, "alert.category").cells[0],
            Value::Str("Potential Corporate Privacy Violation".into())
        );
        assert_eq!(col(&cols, "alert.severity").ty, ColType::Int);
        assert_eq!(col(&cols, "alert.severity").cells[0], Value::Int(1));
        assert_eq!(
            col(&cols, "alert.signature_id").cells[0],
            Value::Int(2010935)
        );
        // The dns event has no alert.* fields → padded null.
        assert_eq!(col(&cols, "alert.category").cells[1], Value::Null);
    }

    #[test]
    fn second_event_type_flattens_its_own_object() {
        let cols = parse(EVE);
        assert_eq!(col(&cols, "event_type").cells[1], Value::Str("dns".into()));
        assert_eq!(
            col(&cols, "dns.rrname").cells[1],
            Value::Str("example.com".into())
        );
        assert_eq!(col(&cols, "dns.rrname").cells[0], Value::Null); // alert row
    }

    #[test]
    fn arrays_are_kept_as_canonical_json() {
        let cols = parse(EVE);
        assert_eq!(
            col(&cols, "metadata").cells[0],
            Value::Str("[\"a\",\"b\"]".into())
        );
    }

    #[test]
    fn flatten_units() {
        let mut row = BTreeMap::new();
        flatten(
            "",
            &serde_json::json!({"a": {"b": {"c": 5}}, "d": 2}),
            &mut row,
        );
        assert_eq!(row.get("a.b.c"), Some(&Value::Int(5))); // deep nesting
        assert_eq!(row.get("d"), Some(&Value::Int(2)));
        assert_eq!(row.len(), 2);
    }

    #[test]
    fn malformed_events_error() {
        assert!(matches!(
            EveParser.parse("-", b"not json\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            EveParser.parse("-", b"[1,2,3]\n"), // valid JSON, not an object
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_event_type_and_timestamp() {
        assert_eq!(EveParser.sniff(EVE.as_bytes()), Some(STRONG));
        // event_type must be a string AND timestamp present.
        assert_eq!(
            EveParser.sniff(br#"{"event_type":"alert","timestamp":"t"}"#),
            Some(STRONG)
        );
        assert_eq!(
            EveParser.sniff(br#"{"event_type":"alert"}"#),
            None,
            "no timestamp"
        );
        assert_eq!(
            EveParser.sniff(br#"{"event_type":5,"timestamp":"t"}"#),
            None,
            "event_type not a string"
        );
        // Generic NDJSON without the EVE signature is not EVE.
        assert_eq!(EveParser.sniff(b"{\"a\":1}\n{\"a\":2}\n"), None);
        assert_eq!(EveParser.sniff(b"a,b,c\n1,2,3"), None); // not JSON
    }

    #[test]
    fn claims_no_extension() {
        assert!(EveParser.extensions().is_empty());
    }

    #[test]
    fn resolves_eve_over_ndjson_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("-", EVE.as_bytes()).unwrap().id(), "eve");
        // Generic NDJSON (no EVE signature) is still NDJSON.
        assert_eq!(
            reg.resolve("-", b"{\"a\":1}\n{\"a\":2}\n").unwrap().id(),
            "ndjson"
        );
    }
}
