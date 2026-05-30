//! JSON document parser: an array of records, a lone object (one row), or a
//! scalar/array (one `value` cell).

use crate::parser::{Confidence, FormatParser, TEXT};
use crate::table::TableBuilder;
use ax_core::{AxError, Column};

#[derive(Debug, Default, Clone)]
pub struct JsonParser;

impl FormatParser for JsonParser {
    fn id(&self) -> &'static str {
        "json"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["json"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let first = text.trim_start().chars().next()?;
        // A leading `[` or `{` is a JSON document. NDJSON outranks this when it
        // sees repeated object-lines (see ndjson.rs).
        (first == '[' || first == '{').then_some(TEXT)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let val: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| AxError::Parse {
            format: self.id().to_string(),
            message: e.to_string(),
        })?;
        let mut builder = TableBuilder::new();
        match val {
            serde_json::Value::Array(items) => {
                for item in items {
                    builder.push_value(item);
                }
            }
            other => builder.push_value(other),
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    #[test]
    fn array_of_objects() {
        let cols = JsonParser
            .parse("d.json", br#"[{"x":10},{"x":20},{"x":30}]"#)
            .unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].name, "x");
        assert_eq!(cols[0].ty, ColType::Int);
        assert_eq!(cols[0].len(), 3);
    }

    #[test]
    fn scalar_array_goes_to_value_column() {
        let cols = JsonParser.parse("d.json", b"[1,2,3]").unwrap();
        assert_eq!(cols[0].name, "value");
        assert_eq!(cols[0].numeric(), vec![1.0, 2.0, 3.0]);
    }

    #[test]
    fn sniff_recognizes_json_shapes() {
        assert_eq!(JsonParser.sniff(b"[1,2]"), Some(TEXT));
        assert_eq!(JsonParser.sniff(b"  {\"a\":1}"), Some(TEXT));
        assert_eq!(JsonParser.sniff(b"a,b"), None);
    }

    #[test]
    fn malformed_json_errors() {
        assert!(matches!(
            JsonParser.parse("d.json", b"{not json"),
            Err(AxError::Parse { .. })
        ));
    }
}
