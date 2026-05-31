//! Windows Event Log (EVTX) parser — central to endpoint forensics.
//!
//! EVTX is a binary chunked format; the heavy lifting (BinXML decoding) is
//! delegated to the `evtx` crate, which yields one `serde_json::Value` per event
//! plus the record id and timestamp. We flatten each event into dotted columns
//! (`Event.System.EventID`, `Event.System.Provider.#attributes.Name`,
//! `Event.EventData.TargetUserName`, …) and synthesize `eventRecordId` and
//! `timestampEpoch` (Unix seconds). That gives the detectors what the issue
//! wants: `Event.System.EventID` for rare event-ID `point` detection and logon
//! `dist` drift, `timestampEpoch` for off-hours `contextual` (`--period 24`).
//!
//! Binary magic `ElfFile\0` (confidence `MAGIC`); extension `.evtx`. The `evtx`
//! crate decodes chunks in parallel but yields records in file order, so output
//! is deterministic. Behind the default-on `evtx` feature.

use crate::infer;
use crate::parser::{Confidence, FormatParser, MAGIC};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use serde_json::Value as J;
use std::collections::BTreeMap;

/// The 8-byte EVTX file-header magic.
const EVTX_MAGIC: &[u8] = b"ElfFile\x00";

#[derive(Debug, Default, Clone)]
pub struct EvtxParser;

/// Flattens a decoded event into dotted columns; scalars and arrays are leaves
/// (arrays kept as canonical JSON via [`infer::json_to_value`]).
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

/// Builds one row from a decoded EVTX record: the flattened event plus the
/// synthesized `eventRecordId` and `timestampEpoch` columns.
fn record_to_row(data: &J, event_record_id: i64, epoch_seconds: i64) -> BTreeMap<String, Value> {
    let mut row = BTreeMap::new();
    flatten("", data, &mut row);
    row.insert("eventRecordId".to_string(), Value::Int(event_record_id));
    row.insert("timestampEpoch".to_string(), Value::Int(epoch_seconds));
    row
}

impl EvtxParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for EvtxParser {
    fn id(&self) -> &'static str {
        "evtx"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["evtx"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        bytes.starts_with(EVTX_MAGIC).then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let mut parser = evtx::EvtxParser::from_buffer(bytes.to_vec()).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for record in parser.records_json_value() {
            let record = record.map_err(|e| self.err(e))?;
            let row = record_to_row(
                &record.data,
                record.event_record_id as i64,
                record.timestamp.as_second(),
            );
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    /// A structurally-valid but empty EVTX: a 4096-byte file header with the
    /// magic and `header_block_size = 4096`, and no chunk data — so the `evtx`
    /// crate parses it and yields zero records. (A real EVTX with records needs a
    /// binary fixture; the per-record extraction is unit-tested via
    /// [`record_to_row`] below.)
    fn empty_evtx() -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[0..8].copy_from_slice(EVTX_MAGIC);
        buf[32..36].copy_from_slice(&128u32.to_le_bytes()); // header_size
        buf[36..38].copy_from_slice(&1u16.to_le_bytes()); // minor version
        buf[38..40].copy_from_slice(&3u16.to_le_bytes()); // major version
        buf[40..42].copy_from_slice(&4096u16.to_le_bytes()); // header_block_size
        buf
    }

    #[test]
    fn valid_empty_file_roundtrips_to_no_rows() {
        let cols = EvtxParser.parse("x.evtx", &empty_evtx()).unwrap();
        assert!(cols.is_empty(), "no records → no columns");
    }

    #[test]
    fn record_to_row_flattens_event_and_adds_synthetic_columns() {
        // A logon-shaped EVTX event (Security 4624).
        let data = serde_json::json!({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "Computer": "WIN-HOST",
                    "Level": 0
                },
                "EventData": {"TargetUserName": "alice", "LogonType": 2}
            }
        });
        let row = record_to_row(&data, 4242, 1_609_459_200);

        assert_eq!(row.get("Event.System.EventID"), Some(&Value::Int(4624)));
        assert_eq!(
            row.get("Event.System.Provider.#attributes.Name"),
            Some(&Value::Str("Microsoft-Windows-Security-Auditing".into()))
        );
        assert_eq!(
            row.get("Event.EventData.TargetUserName"),
            Some(&Value::Str("alice".into()))
        );
        assert_eq!(row.get("Event.EventData.LogonType"), Some(&Value::Int(2)));
        assert_eq!(row.get("eventRecordId"), Some(&Value::Int(4242)));
        assert_eq!(row.get("timestampEpoch"), Some(&Value::Int(1_609_459_200)));
    }

    #[test]
    fn flatten_keeps_arrays_as_json_and_recurses_objects() {
        let mut row = BTreeMap::new();
        flatten(
            "",
            &serde_json::json!({"a": {"b": 1}, "c": [1, 2]}),
            &mut row,
        );
        assert_eq!(row.get("a.b"), Some(&Value::Int(1)));
        assert_eq!(row.get("c"), Some(&Value::Str("[1,2]".into()))); // array → canonical JSON
    }

    #[test]
    fn end_to_end_columns_via_builder() {
        // Two synthesized rows through the same path parse() uses, to pin the
        // typed columns and null-padding the detectors consume.
        let mut builder = TableBuilder::new();
        builder.push_row(record_to_row(
            &serde_json::json!({"Event": {"System": {"EventID": 4624}}}),
            1,
            100,
        ));
        builder.push_row(record_to_row(
            &serde_json::json!({"Event": {"System": {"EventID": 4625}}}),
            2,
            200,
        ));
        let cols = builder.finish();
        let eid = cols
            .iter()
            .find(|c| c.name == "Event.System.EventID")
            .unwrap();
        assert_eq!(eid.ty, ColType::Int);
        assert_eq!(eid.cells, vec![Value::Int(4624), Value::Int(4625)]);
    }

    #[test]
    fn malformed_input_errors() {
        // Wrong magic / not an EVTX file.
        assert!(matches!(
            EvtxParser.parse("x.evtx", b"not an evtx file at all"),
            Err(AxError::Parse { .. })
        ));
        // Magic present but truncated header.
        assert!(matches!(
            EvtxParser.parse("x.evtx", b"ElfFile\x00short"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_magic() {
        assert_eq!(EvtxParser.sniff(&empty_evtx()), Some(MAGIC));
        assert_eq!(EvtxParser.sniff(b"ElfFile\x00....."), Some(MAGIC));
        assert_eq!(EvtxParser.sniff(b"ElfFile"), None); // missing the NUL byte
        assert_eq!(EvtxParser.sniff(b"PAR1...."), None); // parquet, not evtx
        assert_eq!(EvtxParser.sniff(b"{\"a\":1}"), None);
    }

    #[test]
    fn claims_evtx_extension() {
        assert_eq!(EvtxParser.extensions(), &["evtx"]);
    }

    #[test]
    fn resolves_by_extension_and_magic() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("Security.evtx", b"zz").unwrap().id(), "evtx");
        assert_eq!(reg.resolve("-", &empty_evtx()).unwrap().id(), "evtx");
    }
}
