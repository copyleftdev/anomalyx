//! AWS CloudTrail parser — the audit trail for AWS API activity.
//!
//! A CloudTrail file is a single JSON document with a top-level `Records` array;
//! each record is one API call. We flatten each record to **one row**, depth-1:
//! top-level scalars become columns (`eventName`, `eventSource`,
//! `sourceIPAddress`, …), and one level into nested objects
//! (`userIdentity.userName`, `userIdentity.type`); anything deeper or array-
//! valued (`requestParameters`, `responseElements`) is kept as canonical JSON,
//! so a varied per-API payload doesn't explode the schema.
//!
//! We also synthesize **`eventEpoch`** — the RFC 3339 `eventTime` parsed to Unix
//! seconds (deterministic; no wall clock) — so `--cadence eventEpoch` and the
//! `contextual` detector (`--period 24`) can read the call series for off-hours /
//! automated-pattern anomalies, while `eventName` feeds rare-API `dist` drift.
//!
//! Detected by a `Records` array whose entries carry `eventName`; claims no
//! extension (CloudTrail is delivered as `*.json`, owned by the JSON parser —
//! pipe it on stdin for CloudTrail-aware flattening).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use chrono::DateTime;
use serde_json::Value as J;
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct CloudTrailParser;

/// Flattens one record depth-1: top-level scalars keep their name, nested
/// objects contribute `parent.child` columns, and anything deeper (or an array)
/// is lowered to its canonical JSON string by [`infer::json_to_value`].
fn flatten_record(record: &serde_json::Map<String, J>, row: &mut BTreeMap<String, Value>) {
    for (key, value) in record {
        match value {
            J::Object(inner) => {
                for (child, child_value) in inner {
                    row.insert(format!("{key}.{child}"), infer::json_to_value(child_value));
                }
            }
            scalar_or_array => {
                row.insert(key.clone(), infer::json_to_value(scalar_or_array));
            }
        }
    }
}

impl CloudTrailParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for CloudTrailParser {
    fn id(&self) -> &'static str {
        "cloudtrail"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let value: J = serde_json::from_slice(bytes).ok()?;
        let records = value.get("Records").and_then(J::as_array)?;
        // A `Records` array whose entries carry `eventName` is CloudTrail (and not
        // just any JSON that happens to have a "Records" key).
        records
            .first()
            .is_some_and(|r| r.get("eventName").is_some())
            .then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let root: J = serde_json::from_slice(bytes).map_err(|e| self.err(e))?;
        let records = root
            .get("Records")
            .and_then(J::as_array)
            .ok_or_else(|| self.err("not CloudTrail: missing 'Records' array"))?;

        let mut builder = TableBuilder::new();
        for record in records {
            let obj = record
                .as_object()
                .ok_or_else(|| self.err("CloudTrail record is not an object"))?;
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            flatten_record(obj, &mut row);
            // Numeric event time for cadence / contextual analysis.
            if let Some(time) = obj.get("eventTime").and_then(J::as_str) {
                if let Ok(dt) = DateTime::parse_from_rfc3339(time) {
                    row.insert("eventEpoch".into(), Value::Int(dt.timestamp()));
                }
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

    const TRAIL: &str = r#"{
      "Records": [
        {
          "eventVersion": "1.08",
          "eventTime": "2021-01-01T00:00:00Z",
          "eventSource": "s3.amazonaws.com",
          "eventName": "GetObject",
          "awsRegion": "us-east-1",
          "sourceIPAddress": "1.2.3.4",
          "readOnly": true,
          "userIdentity": {"type": "IAMUser", "userName": "alice", "accountId": "111"},
          "requestParameters": {"bucketName": "logs", "key": "a/b"},
          "responseElements": null
        },
        {
          "eventVersion": "1.08",
          "eventTime": "2021-01-01T03:30:00Z",
          "eventSource": "iam.amazonaws.com",
          "eventName": "CreateUser",
          "awsRegion": "us-east-1",
          "sourceIPAddress": "9.9.9.9",
          "readOnly": false,
          "userIdentity": {"type": "AssumedRole", "sessionContext": {"mfa": true}}
        }
      ]
    }"#;

    fn parse(s: &str) -> Vec<Column> {
        CloudTrailParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn one_row_per_record_with_typed_top_level_fields() {
        let cols = parse(TRAIL);
        let name = col(&cols, "eventName");
        assert_eq!(name.cells.len(), 2);
        assert_eq!(name.cells[0], Value::Str("GetObject".into()));
        assert_eq!(name.cells[1], Value::Str("CreateUser".into()));
        assert_eq!(
            col(&cols, "eventSource").cells[1],
            Value::Str("iam.amazonaws.com".into())
        );
        assert_eq!(col(&cols, "readOnly").ty, ColType::Bool);
        assert_eq!(col(&cols, "readOnly").cells[0], Value::Bool(true));
    }

    #[test]
    fn event_time_is_parsed_to_epoch_seconds() {
        let cols = parse(TRAIL);
        let epoch = col(&cols, "eventEpoch");
        assert_eq!(epoch.ty, ColType::Int);
        assert_eq!(epoch.cells[0], Value::Int(1_609_459_200)); // 2021-01-01T00:00:00Z
        assert_eq!(epoch.cells[1], Value::Int(1_609_471_800)); // +3h30m (12600s)
    }

    #[test]
    fn nested_objects_flatten_one_level() {
        let cols = parse(TRAIL);
        assert_eq!(
            col(&cols, "userIdentity.userName").cells[0],
            Value::Str("alice".into())
        );
        assert_eq!(
            col(&cols, "userIdentity.type").cells[1],
            Value::Str("AssumedRole".into())
        );
        // requestParameters flattens one level too.
        assert_eq!(
            col(&cols, "requestParameters.bucketName").cells[0],
            Value::Str("logs".into())
        );
        // userName absent on the second record → padded null.
        assert_eq!(col(&cols, "userIdentity.userName").cells[1], Value::Null);
    }

    #[test]
    fn deeper_nesting_is_kept_as_canonical_json() {
        let cols = parse(TRAIL);
        // sessionContext is an object nested inside userIdentity → stringified.
        assert_eq!(
            col(&cols, "userIdentity.sessionContext").cells[1],
            Value::Str("{\"mfa\":true}".into())
        );
    }

    #[test]
    fn flatten_record_units() {
        let mut row = BTreeMap::new();
        let serde_json::Value::Object(obj) =
            serde_json::json!({"a": 1, "b": {"c": "x", "d": {"e": 2}}})
        else {
            unreachable!()
        };
        flatten_record(&obj, &mut row);
        assert_eq!(row.get("a"), Some(&Value::Int(1))); // top-level scalar
        assert_eq!(row.get("b.c"), Some(&Value::Str("x".into()))); // one level in
                                                                   // b.d is an object → canonical JSON string, not b.d.e.
        assert_eq!(row.get("b.d"), Some(&Value::Str("{\"e\":2}".into())));
        assert_eq!(row.get("b.d.e"), None);
    }

    #[test]
    fn malformed_and_non_cloudtrail_error() {
        assert!(matches!(
            CloudTrailParser.parse("-", b"{not json"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            CloudTrailParser.parse("-", br#"{"foo": 1}"#),
            Err(AxError::Parse { .. })
        ));
        // A record that is not an object.
        assert!(matches!(
            CloudTrailParser.parse("-", br#"{"Records": [1, 2]}"#),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_records_with_event_name() {
        assert_eq!(CloudTrailParser.sniff(TRAIL.as_bytes()), Some(STRONG));
        // A Records array without eventName entries is not CloudTrail.
        assert_eq!(CloudTrailParser.sniff(br#"{"Records": [{"x": 1}]}"#), None);
        assert_eq!(CloudTrailParser.sniff(br#"{"Records": []}"#), None); // empty
        assert_eq!(CloudTrailParser.sniff(br#"{"Records": 5}"#), None); // not an array
        assert_eq!(CloudTrailParser.sniff(br#"{"foo": 1}"#), None);
        assert_eq!(CloudTrailParser.sniff(b"a,b,c\n1,2,3"), None); // not JSON
    }

    #[test]
    fn claims_no_extension() {
        assert!(CloudTrailParser.extensions().is_empty());
    }

    #[test]
    fn resolves_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(
            reg.resolve("-", TRAIL.as_bytes()).unwrap().id(),
            "cloudtrail"
        );
    }
}
