//! Newline-delimited JSON parser: one JSON value per line. Scalar or array
//! lines are placed under the synthetic `value` column.

use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column};

#[derive(Debug, Default, Clone)]
pub struct NdjsonParser;

impl FormatParser for NdjsonParser {
    fn id(&self) -> &'static str {
        "ndjson"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ndjson", "jsonl"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let trimmed = text.trim_start();
        if !trimmed.starts_with('{') {
            return None;
        }
        // Two or more object-leading lines distinguishes NDJSON from a single
        // JSON object; this outranks JsonParser's TEXT confidence.
        let object_lines = trimmed
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(3)
            .filter(|l| l.trim_start().starts_with('{'))
            .count();
        (object_lines >= 2).then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| AxError::Parse {
            format: self.id().to_string(),
            message: e.to_string(),
        })?;
        let mut builder = TableBuilder::new();
        for (lineno, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let val: serde_json::Value =
                serde_json::from_str(line).map_err(|e| AxError::Parse {
                    format: self.id().to_string(),
                    message: format!("line {}: {e}", lineno + 1),
                })?;
            builder.push_value(val);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_union_pads_missing() {
        let cols = NdjsonParser
            .parse("-", b"{\"a\":1}\n{\"a\":2,\"b\":9}\n")
            .unwrap();
        let bcol = cols.iter().find(|c| c.name == "b").unwrap();
        assert_eq!(bcol.null_count(), 1);
        assert_eq!(cols.iter().find(|c| c.name == "a").unwrap().len(), 2);
    }

    #[test]
    fn blank_lines_skipped() {
        let cols = NdjsonParser
            .parse("-", b"{\"a\":1}\n\n{\"a\":2}\n")
            .unwrap();
        assert_eq!(cols[0].len(), 2);
    }

    #[test]
    fn sniff_needs_repeated_object_lines() {
        assert_eq!(NdjsonParser.sniff(b"{\"a\":1}\n{\"a\":2}\n"), Some(STRONG));
        assert_eq!(NdjsonParser.sniff(b"{\"a\":1}"), None); // single object → JsonParser's job
        assert_eq!(NdjsonParser.sniff(b"[1,2]"), None);
    }

    #[test]
    fn malformed_line_errors_with_line_number() {
        let err = NdjsonParser.parse("-", b"{\"a\":1}\n{bad}\n").unwrap_err();
        assert!(matches!(err, AxError::Parse { .. }));
        assert!(format!("{err}").contains("line 2"));
    }
}
