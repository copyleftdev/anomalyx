//! systemd journal export parser — `journalctl -o json`.
//!
//! The export is NDJSON (one JSON object per log entry), but journald encodes
//! *every* value as a string — including numeric fields like
//! `__REALTIME_TIMESTAMP` (microseconds since epoch), `PRIORITY`, and `_PID`.
//! Generic NDJSON would leave those as `Str`, where the numeric detectors can't
//! reach them. So this parser type-**coerces** each string scalar (the same
//! inference CSV uses): `__REALTIME_TIMESTAMP` → `Int` for `--cadence` /
//! `coll.cusum` event-rate analysis, `PRIORITY` → `Int`, while `_SYSTEMD_UNIT`
//! stays a `Str` for rare-unit `dist` drift. A field that appears as an array
//! (multi-value, or a non-UTF-8 byte field) is kept as its canonical JSON string.
//!
//! Detected by journald's signature trusted fields (`__REALTIME_TIMESTAMP` /
//! `__CURSOR` / `_SYSTEMD_UNIT`); claims no extension (the JSON export is
//! generically `*.json`, and `.journal` is the unrelated binary format).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use serde_json::Value as J;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct JournalParser;

/// Trusted/addressing fields that `journalctl -o json` always emits — their
/// presence is the journal signature, distinguishing it from generic NDJSON.
const SIGNATURE_KEYS: [&str; 3] = ["__REALTIME_TIMESTAMP", "__CURSOR", "_SYSTEMD_UNIT"];

fn looks_like_journal(obj: &serde_json::Map<String, J>) -> bool {
    SIGNATURE_KEYS.iter().any(|k| obj.contains_key(*k))
}

impl JournalParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for JournalParser {
    fn id(&self) -> &'static str {
        "journal"
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
            .is_some_and(looks_like_journal)
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
                .ok_or_else(|| self.err("journal entry is not a JSON object"))?;
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for (key, val) in obj {
                // journald stores everything as a string: infer the type so
                // numeric fields become numeric columns. Arrays/objects keep the
                // existing JSON lowering (canonical string for non-scalars).
                let cell = match val {
                    J::String(s) => infer::infer_scalar(s),
                    other => infer::json_to_value(other),
                };
                row.insert(key.clone(), cell);
            }
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const JOURNAL: &str = concat!(
        r#"{"__CURSOR":"s=a","__REALTIME_TIMESTAMP":"1612345678000000","__MONOTONIC_TIMESTAMP":"1000","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"6","_PID":"1234","MESSAGE":"Accepted password","_HOSTNAME":"host"}"#,
        "\n",
        r#"{"__CURSOR":"s=b","__REALTIME_TIMESTAMP":"1612345679000000","_SYSTEMD_UNIT":"cron.service","PRIORITY":"5","MESSAGE":"job done"}"#,
        "\n",
        r#"{"__CURSOR":"s=c","__REALTIME_TIMESTAMP":"1612345680000000","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"3","MESSAGE":[72,73]}"#,
        "\n",
    );

    fn parse(s: &str) -> Vec<Column> {
        JournalParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn numeric_string_fields_are_coerced() {
        let cols = parse(JOURNAL);
        let ts = col(&cols, "__REALTIME_TIMESTAMP");
        assert_eq!(ts.ty, ColType::Int, "timestamp coerced for cadence/cusum");
        assert_eq!(ts.cells[0], Value::Int(1_612_345_678_000_000));
        let prio = col(&cols, "PRIORITY");
        assert_eq!(prio.ty, ColType::Int);
        assert_eq!(prio.cells[0], Value::Int(6));
        assert_eq!(prio.cells[2], Value::Int(3));
        assert_eq!(col(&cols, "_PID").cells[0], Value::Int(1234));
    }

    #[test]
    fn unit_and_message_stay_strings() {
        let cols = parse(JOURNAL);
        let unit = col(&cols, "_SYSTEMD_UNIT");
        assert_eq!(unit.ty, ColType::Str, "unit stays categorical for dist");
        assert_eq!(unit.cells[0], Value::Str("sshd.service".into()));
        assert_eq!(
            col(&cols, "MESSAGE").cells[0],
            Value::Str("Accepted password".into())
        );
    }

    #[test]
    fn missing_fields_pad_with_null() {
        let cols = parse(JOURNAL);
        // _PID and _HOSTNAME appear only on the first entry.
        assert_eq!(col(&cols, "_PID").null_count(), 2);
        assert_eq!(col(&cols, "_HOSTNAME").null_count(), 2);
    }

    #[test]
    fn array_valued_field_is_canonical_json() {
        // A non-UTF-8 MESSAGE is exported as a byte array; keep it as a string.
        let cols = parse(JOURNAL);
        assert_eq!(col(&cols, "MESSAGE").cells[2], Value::Str("[72,73]".into()));
    }

    #[test]
    fn malformed_entries_error() {
        assert!(matches!(
            JournalParser.parse("-", b"not json\n"),
            Err(AxError::Parse { .. })
        ));
        // Valid JSON but not an object (journald entries are always objects).
        assert!(matches!(
            JournalParser.parse("-", b"[1,2,3]\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_journald_signature() {
        assert_eq!(JournalParser.sniff(JOURNAL.as_bytes()), Some(STRONG));
        // A single signature key is enough (covers any-vs-all).
        assert_eq!(
            JournalParser.sniff(br#"{"__CURSOR":"x","MESSAGE":"y"}"#),
            Some(STRONG)
        );
        // Generic NDJSON with no journald field is NOT journal.
        assert_eq!(JournalParser.sniff(b"{\"a\":1}\n{\"a\":2}\n"), None);
        assert_eq!(JournalParser.sniff(br#"{"foo":1}"#), None);
        assert_eq!(JournalParser.sniff(b"a,b,c\n1,2,3"), None); // not JSON
    }

    #[test]
    fn claims_no_extension() {
        assert!(JournalParser.extensions().is_empty());
    }

    #[test]
    fn resolves_journal_over_ndjson_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        // journald content wins the journal signature over generic NDJSON.
        assert_eq!(
            reg.resolve("-", JOURNAL.as_bytes()).unwrap().id(),
            "journal"
        );
        // Generic NDJSON (no signature) is still NDJSON.
        assert_eq!(
            reg.resolve("-", b"{\"a\":1}\n{\"a\":2}\n").unwrap().id(),
            "ndjson"
        );
    }
}
