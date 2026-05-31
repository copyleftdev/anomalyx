//! YAML parser — Kubernetes manifests and CI configs.
//!
//! Each YAML document becomes a record (a sequence document expands to one row
//! per element, like a JSON array), deserialized into a [`serde_json::Value`]
//! and lowered through the same union-key [`TableBuilder`] path as JSON — so a
//! field present in one manifest but absent in another is an explicit `Null`,
//! which is exactly what `struct.schema --baseline` reads as added/removed keys.
//! Multi-document streams (`---` separators) are fully supported; an empty
//! document produces no row.

use crate::parser::{Confidence, FormatParser, TEXT};
use crate::table::TableBuilder;
use ax_core::{AxError, Column};
use serde::Deserialize;

#[derive(Debug, Default, Clone)]
pub struct YamlParser;

/// A `key:` mapping line — a bareword key (`[A-Za-z0-9._-]`) followed by `:` and
/// then either end-of-line or a space. This is the distinctive YAML shape we
/// sniff for; it deliberately rejects `12:00` (no space after colon) and CSV.
fn is_mapping_key(line: &str) -> bool {
    match line.find(':') {
        Some(i) => {
            let (key, after) = (&line[..i], &line[i + 1..]);
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
                && (after.is_empty() || after.starts_with(' '))
        }
        None => false,
    }
}

/// A block-sequence item: `-` alone, or `- ` then content.
fn is_list_item(line: &str) -> bool {
    line == "-" || line.starts_with("- ")
}

impl YamlParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for YamlParser {
    fn id(&self) -> &'static str {
        "yaml"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["yaml", "yml"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let lt = line.trim_start();
            if lt.starts_with('#') {
                continue; // YAML comment — keep looking
            }
            // The first meaningful line decides: a document marker, a mapping
            // key, or a list item is YAML; anything else clearly is not.
            let yaml_like =
                lt == "---" || lt.starts_with("--- ") || is_mapping_key(lt) || is_list_item(lt);
            return yaml_like.then_some(TEXT);
        }
        None
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let mut builder = TableBuilder::new();
        for document in serde_yaml::Deserializer::from_slice(bytes) {
            let val = serde_json::Value::deserialize(document).map_err(|e| self.err(e))?;
            match val {
                serde_json::Value::Array(items) => {
                    for item in items {
                        builder.push_value(item);
                    }
                }
                serde_json::Value::Null => {} // empty document → no row
                other => builder.push_value(other),
            }
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{ColType, Value};

    fn parse(s: &str) -> Vec<Column> {
        YamlParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    const MANIFEST: &str = "\
apiVersion: apps/v1
kind: Deployment
replicas: 3
";

    #[test]
    fn parses_a_mapping_document_with_typed_cells() {
        let cols = parse(MANIFEST);
        assert_eq!(col(&cols, "kind").cells[0], Value::Str("Deployment".into()));
        assert_eq!(col(&cols, "replicas").ty, ColType::Int);
        assert_eq!(col(&cols, "replicas").cells[0], Value::Int(3));
        assert_eq!(
            col(&cols, "apiVersion").cells[0],
            Value::Str("apps/v1".into())
        );
    }

    #[test]
    fn multi_document_stream_is_one_row_per_doc() {
        // The cross-manifest case `struct.schema --baseline` cares about: a key
        // present in one doc, absent in the next, pads with Null.
        let cols = parse("kind: A\nfoo: 1\n---\nkind: B\n");
        let kind = col(&cols, "kind");
        assert_eq!(kind.cells.len(), 2);
        assert_eq!(kind.cells[0], Value::Str("A".into()));
        assert_eq!(kind.cells[1], Value::Str("B".into()));
        assert_eq!(col(&cols, "foo").cells[1], Value::Null, "absent in doc 2");
    }

    #[test]
    fn sequence_document_expands_to_rows() {
        let cols = parse("- x: 1\n- x: 2\n");
        assert_eq!(col(&cols, "x").cells, vec![Value::Int(1), Value::Int(2)]);
    }

    #[test]
    fn empty_document_produces_no_row() {
        // A trailing `---` leaves an empty doc; it must not add a blank row.
        let cols = parse("kind: A\n---\n");
        assert_eq!(col(&cols, "kind").cells.len(), 1);
    }

    #[test]
    fn malformed_yaml_errors() {
        // A mapping value that is itself a mapping inline is invalid YAML.
        assert!(matches!(
            YamlParser.parse("-", b"a: b: c\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn mapping_key_classification() {
        assert!(is_mapping_key("apiVersion: v1"));
        assert!(is_mapping_key("a.b-c_d: x"));
        assert!(is_mapping_key("kind:")); // key with empty value (block follows)
        assert!(!is_mapping_key("12:00")); // no space after colon → not a key
        assert!(!is_mapping_key(": x")); // empty key
        assert!(!is_mapping_key("no colon here"));
        assert!(!is_mapping_key("foo bar: x")); // space in key
    }

    #[test]
    fn list_item_classification() {
        assert!(is_list_item("- item"));
        assert!(is_list_item("-"));
        assert!(!is_list_item("-nospace"));
        assert!(!is_list_item("notalist"));
    }

    #[test]
    fn sniff_recognizes_yaml_shapes() {
        assert_eq!(YamlParser.sniff(MANIFEST.as_bytes()), Some(TEXT));
        assert_eq!(YamlParser.sniff(b"---\nkind: Pod\n"), Some(TEXT)); // doc marker
        assert_eq!(YamlParser.sniff(b"--- {inline: 1}\n"), Some(TEXT)); // inline marker
        assert_eq!(YamlParser.sniff(b"- a\n- b\n"), Some(TEXT)); // sequence
        assert_eq!(YamlParser.sniff(b"# header\nkind: Pod\n"), Some(TEXT)); // comment first
        assert_eq!(YamlParser.sniff(b"\n\nkind: Pod\n"), Some(TEXT)); // blank lines first
    }

    #[test]
    fn sniff_rejects_non_yaml() {
        assert_eq!(YamlParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
        assert_eq!(YamlParser.sniff(b"k=1 v=2\n"), None); // logfmt
        assert_eq!(YamlParser.sniff(b"{\"a\":1}"), None); // JSON object
        assert_eq!(YamlParser.sniff(b"12:00 something\n"), None); // not a key
        assert_eq!(YamlParser.sniff(b"hello world\n"), None); // prose
        assert_eq!(
            YamlParser.sniff(b"hello world\nkind: Pod\n"),
            None,
            "a non-YAML first line is decisive; we do not scan past it"
        );
    }

    #[test]
    fn claims_yaml_extensions() {
        assert_eq!(YamlParser.extensions(), &["yaml", "yml"]);
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("deploy.yaml", b"x: 1").unwrap().id(), "yaml");
        assert_eq!(reg.resolve("deploy.yml", b"x: 1").unwrap().id(), "yaml");
        assert_eq!(
            reg.resolve("-", MANIFEST.as_bytes()).unwrap().id(),
            "yaml",
            "routed by content sniff"
        );
    }
}
