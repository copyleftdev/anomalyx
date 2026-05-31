//! osquery results parser — endpoint fleet telemetry (JSON event log).
//!
//! osquery's results log is NDJSON. Each line carries query metadata (`name`,
//! `hostIdentifier`, `unixTime`, `action`, …) plus the actual result data in
//! either a **differential** `columns` object (one result row) or a **snapshot**
//! array (many result rows). We emit **one row per result**: the metadata
//! columns plus the result fields under a `columns.<key>` prefix (so a query
//! column named `name` doesn't collide with the query `name`). osquery stringifies
//! every column value, so those are type-coerced (`pid` `"123"` → `Int`) — which
//! lets `structural`/`dist` read fleet-posture drift against a baseline snapshot.
//!
//! Detected by the `hostIdentifier` + (`columns` | `snapshot`) signature; claims
//! no extension (the results log is generically `*.log`).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use serde_json::Value as J;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct OsqueryParser;

fn looks_like_osquery(obj: &serde_json::Map<String, J>) -> bool {
    obj.contains_key("hostIdentifier")
        && (obj.get("columns").is_some_and(J::is_object)
            || obj.get("snapshot").is_some_and(J::is_array))
}

/// Adds a result object's fields as `columns.<key>` cells, type-coercing the
/// stringified values osquery emits.
fn add_columns(result: &serde_json::Map<String, J>, row: &mut BTreeMap<String, Value>) {
    for (key, value) in result {
        let cell = match value {
            J::String(s) => infer::infer_scalar(s),
            other => infer::json_to_value(other),
        };
        row.insert(format!("columns.{key}"), cell);
    }
}

impl OsqueryParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for OsqueryParser {
    fn id(&self) -> &'static str {
        "osquery"
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
            .is_some_and(looks_like_osquery)
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
            let obj = value
                .as_object()
                .ok_or_else(|| self.err("osquery result is not a JSON object"))?;

            // Metadata: every top-level scalar except the result payloads.
            let mut meta: BTreeMap<String, Value> = BTreeMap::new();
            for (key, val) in obj {
                if key == "columns" || key == "snapshot" {
                    continue;
                }
                meta.insert(key.clone(), infer::json_to_value(val));
            }

            match (obj.get("columns"), obj.get("snapshot")) {
                // Differential: one result object → one row.
                (Some(J::Object(columns)), _) => {
                    let mut row = meta.clone();
                    add_columns(columns, &mut row);
                    builder.push_row(row);
                }
                // Snapshot: one row per array element (metadata replicated).
                (_, Some(J::Array(snapshot))) => {
                    for element in snapshot {
                        if let Some(result) = element.as_object() {
                            let mut row = meta.clone();
                            add_columns(result, &mut row);
                            builder.push_row(row);
                        }
                    }
                }
                // Neither payload: emit the metadata row as-is.
                _ => builder.push_row(meta),
            }
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const OSQUERY: &str = concat!(
        r#"{"name":"processes","hostIdentifier":"host1","unixTime":1609459200,"action":"added","columns":{"pid":"123","name":"sshd","path":"/usr/sbin/sshd"}}"#,
        "\n",
        r#"{"name":"processes","hostIdentifier":"host1","unixTime":1609459260,"action":"removed","columns":{"pid":"99","name":"bash"}}"#,
        "\n",
        r#"{"name":"users","hostIdentifier":"host2","unixTime":1609459300,"action":"snapshot","snapshot":[{"uid":"0","username":"root"},{"uid":"1000","username":"alice"}]}"#,
        "\n",
    );

    fn parse(s: &str) -> Vec<Column> {
        OsqueryParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn differential_columns_are_prefixed_and_coerced() {
        let cols = parse(OSQUERY);
        let pid = col(&cols, "columns.pid");
        assert_eq!(pid.ty, ColType::Int, "stringified pid coerced to int");
        assert_eq!(pid.cells[0], Value::Int(123));
        assert_eq!(pid.cells[1], Value::Int(99));
        // The query name (top-level) and the column name stay distinct.
        assert_eq!(col(&cols, "name").cells[0], Value::Str("processes".into()));
        assert_eq!(
            col(&cols, "columns.name").cells[0],
            Value::Str("sshd".into())
        );
    }

    #[test]
    fn metadata_is_typed() {
        let cols = parse(OSQUERY);
        assert_eq!(col(&cols, "unixTime").ty, ColType::Int);
        assert_eq!(col(&cols, "unixTime").cells[0], Value::Int(1609459200));
        assert_eq!(col(&cols, "action").cells[1], Value::Str("removed".into()));
        assert_eq!(
            col(&cols, "hostIdentifier").cells[0],
            Value::Str("host1".into())
        );
    }

    #[test]
    fn snapshot_expands_to_one_row_per_element() {
        let cols = parse(OSQUERY);
        // 2 differential rows + 2 snapshot rows = 4.
        assert_eq!(col(&cols, "name").cells.len(), 4);
        let uid = col(&cols, "columns.uid");
        assert_eq!(uid.cells[2], Value::Int(0)); // root
        assert_eq!(uid.cells[3], Value::Int(1000)); // alice
        assert_eq!(
            col(&cols, "columns.username").cells[3],
            Value::Str("alice".into())
        );
        // Metadata replicated onto each snapshot row.
        assert_eq!(
            col(&cols, "hostIdentifier").cells[2],
            Value::Str("host2".into())
        );
        assert_eq!(col(&cols, "action").cells[2], Value::Str("snapshot".into()));
        // A differential-only column is null on the snapshot rows.
        assert_eq!(col(&cols, "columns.pid").cells[2], Value::Null);
        // The raw payloads are flattened, never emitted as bare columns.
        assert!(cols.iter().all(|c| c.name != "columns"));
        assert!(cols.iter().all(|c| c.name != "snapshot"));
    }

    #[test]
    fn add_columns_units() {
        let mut row = BTreeMap::new();
        let serde_json::Value::Object(obj) = serde_json::json!({"pid": "5", "name": "x"}) else {
            unreachable!()
        };
        add_columns(&obj, &mut row);
        assert_eq!(row.get("columns.pid"), Some(&Value::Int(5)));
        assert_eq!(row.get("columns.name"), Some(&Value::Str("x".into())));
    }

    #[test]
    fn malformed_events_error() {
        assert!(matches!(
            OsqueryParser.parse("-", b"not json\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            OsqueryParser.parse("-", b"[1,2,3]\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_host_identifier_and_payload() {
        assert_eq!(OsqueryParser.sniff(OSQUERY.as_bytes()), Some(STRONG));
        // snapshot form is also recognized.
        assert_eq!(
            OsqueryParser.sniff(br#"{"hostIdentifier":"h","snapshot":[{"a":"1"}]}"#),
            Some(STRONG)
        );
        // hostIdentifier alone (no columns/snapshot) is not enough.
        assert_eq!(OsqueryParser.sniff(br#"{"hostIdentifier":"h"}"#), None);
        // columns alone (no hostIdentifier) is not enough.
        assert_eq!(OsqueryParser.sniff(br#"{"columns":{"a":"1"}}"#), None);
        // columns must be an object, snapshot must be an array.
        assert_eq!(
            OsqueryParser.sniff(br#"{"hostIdentifier":"h","columns":5}"#),
            None
        );
        assert_eq!(OsqueryParser.sniff(b"{\"a\":1}\n{\"a\":2}\n"), None); // generic NDJSON
        assert_eq!(OsqueryParser.sniff(b"a,b,c\n1,2,3"), None); // not JSON
    }

    #[test]
    fn claims_no_extension() {
        assert!(OsqueryParser.extensions().is_empty());
    }

    #[test]
    fn resolves_osquery_over_ndjson_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(
            reg.resolve("-", OSQUERY.as_bytes()).unwrap().id(),
            "osquery"
        );
        assert_eq!(
            reg.resolve("-", b"{\"a\":1}\n{\"a\":2}\n").unwrap().id(),
            "ndjson"
        );
    }
}
