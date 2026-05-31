//! XML parser — scan reports (Nessus/OpenVAS), SOAP, and configs.
//!
//! XML is a tree, so we flatten it to rows by finding the **record element**:
//! the most-repeated group of sibling elements (e.g. `<ReportItem>` under a
//! Nessus `<ReportHost>`, or `<vuln>` in a report). Each such element becomes a
//! row whose columns are its **attributes** plus its **leaf child elements**
//! (text-only children), type-inferred. With no repetition the document is a
//! single record (e.g. a config) and the root element becomes one row.
//!
//! Flattened this way it feeds `structural` and `dist` like any other corpus.
//! Detected by an `<?xml` declaration (`STRONG`) or a leading element tag
//! (`TEXT`); extensions `.xml` / `.nessus`.

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG, TEXT};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use roxmltree::{Document, Node};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct XmlParser;

/// Selects the record elements: the largest group of same-named sibling elements
/// (first such group in document order on a tie). Falls back to the root element
/// as a single record when nothing repeats.
fn find_records<'a, 'input>(doc: &'a Document<'input>) -> Vec<Node<'a, 'input>> {
    let mut best: Vec<Node> = Vec::new();
    for parent in doc.descendants().filter(Node::is_element) {
        // Group this parent's direct element children by tag, preserving order.
        let mut groups: Vec<(&str, Vec<Node>)> = Vec::new();
        for child in parent.children().filter(Node::is_element) {
            let name = child.tag_name().name();
            match groups.iter_mut().find(|(n, _)| *n == name) {
                Some(group) => group.1.push(child),
                None => groups.push((name, vec![child])),
            }
        }
        for (_, nodes) in groups {
            if nodes.len() >= 2 && nodes.len() > best.len() {
                best = nodes;
            }
        }
    }
    if best.is_empty() {
        best.push(doc.root_element());
    }
    best
}

/// Is this element a leaf (no child elements of its own)?
fn is_leaf(node: &Node) -> bool {
    !node.children().any(|c| c.is_element())
}

impl XmlParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for XmlParser {
    fn id(&self) -> &'static str {
        "xml"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xml", "nessus"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let trimmed = text.trim_start();
        if trimmed.starts_with("<?xml") {
            return Some(STRONG);
        }
        // A leading element tag (`<` then a name char) is XML; `<` then a digit is
        // a syslog priority, not XML.
        let after = trimmed.strip_prefix('<')?;
        after
            .starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            .then_some(TEXT)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let doc = Document::parse(text).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for record in find_records(&doc) {
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for attr in record.attributes() {
                row.insert(attr.name().to_string(), infer::infer_scalar(attr.value()));
            }
            for child in record.children().filter(Node::is_element) {
                if is_leaf(&child) {
                    let text = child.text().unwrap_or("").trim();
                    let cell = if text.is_empty() {
                        Value::Null
                    } else {
                        infer::infer_scalar(text)
                    };
                    row.insert(child.tag_name().name().to_string(), cell);
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

    const REPORT: &str = r#"<?xml version="1.0"?>
<vulns>
  <vuln id="1" severity="high"><name>SQLi</name><port>443</port></vuln>
  <vuln id="2" severity="low"><name>XSS</name><port>80</port></vuln>
  <vuln id="3" severity="high"><name>RCE</name><port>22</port></vuln>
</vulns>"#;

    fn parse(s: &str) -> Vec<Column> {
        XmlParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn repeated_element_becomes_rows_with_attrs_and_leaf_children() {
        let cols = parse(REPORT);
        // Three <vuln> records.
        assert_eq!(col(&cols, "id").cells.len(), 3);
        // Attributes are columns (id typed Int, severity categorical Str).
        assert_eq!(col(&cols, "id").ty, ColType::Int);
        assert_eq!(
            col(&cols, "id").cells,
            vec![Value::Int(1), Value::Int(2), Value::Int(3)]
        );
        assert_eq!(
            col(&cols, "severity").cells,
            vec![
                Value::Str("high".into()),
                Value::Str("low".into()),
                Value::Str("high".into())
            ]
        );
        // Leaf child elements are columns (name Str, port Int).
        assert_eq!(col(&cols, "name").cells[0], Value::Str("SQLi".into()));
        assert_eq!(col(&cols, "port").ty, ColType::Int);
        assert_eq!(
            col(&cols, "port").cells,
            vec![Value::Int(443), Value::Int(80), Value::Int(22)]
        );
    }

    #[test]
    fn picks_the_deepest_repeated_group_not_a_leaf() {
        // <name> and <port> each occur 3 times globally, but the repeated SIBLING
        // group is <vuln>; the records must be the vulns, not the names.
        assert_eq!(parse(REPORT).len(), 4); // id, severity, name, port columns
        assert_eq!(col(&parse(REPORT), "name").cells.len(), 3);
    }

    #[test]
    fn tie_breaks_to_the_first_repeated_group() {
        // Two groups of equal count (2) under one parent; the FIRST (a) wins, so
        // the rows carry `x`, not `y`.
        let cols = parse(r#"<root><a x="1"/><a x="2"/><b y="3"/><b y="4"/></root>"#);
        assert_eq!(col(&cols, "x").cells, vec![Value::Int(1), Value::Int(2)]);
        assert!(
            cols.iter().all(|c| c.name != "y"),
            "the later group must lose"
        );
    }

    #[test]
    fn non_leaf_children_are_not_flattened() {
        // A child with its own children (<meta>) is not a leaf and must not become
        // a column; only the leaf <tag> does.
        let cols = parse(
            "<items><item id=\"1\"><meta><sub>d</sub></meta><tag>a</tag></item>\
             <item id=\"2\"><meta><sub>d</sub></meta><tag>b</tag></item></items>",
        );
        assert_eq!(
            col(&cols, "tag").cells,
            vec![Value::Str("a".into()), Value::Str("b".into())]
        );
        assert!(
            cols.iter().all(|c| c.name != "meta"),
            "non-leaf child skipped"
        );
    }

    #[test]
    fn no_repetition_treats_root_as_one_record() {
        let cols = parse("<config><host>web01</host><port>8080</port></config>");
        assert_eq!(col(&cols, "host").cells, vec![Value::Str("web01".into())]);
        assert_eq!(col(&cols, "port").cells, vec![Value::Int(8080)]);
    }

    #[test]
    fn empty_leaf_is_null() {
        let cols = parse("<r><a>x</a><b></b></r>");
        assert_eq!(col(&cols, "a").cells[0], Value::Str("x".into()));
        assert_eq!(col(&cols, "b").cells[0], Value::Null);
    }

    #[test]
    fn malformed_xml_errors() {
        assert!(matches!(
            XmlParser.parse("-", b"<unclosed>"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            XmlParser.parse("-", b"not xml at all"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_recognizes_xml() {
        assert_eq!(XmlParser.sniff(REPORT.as_bytes()), Some(STRONG)); // <?xml
        assert_eq!(XmlParser.sniff(b"<vulns><vuln/></vulns>"), Some(TEXT)); // bare element
        assert_eq!(XmlParser.sniff(b"  <root>x</root>"), Some(TEXT)); // leading whitespace
        assert_eq!(XmlParser.sniff(b"<34>Oct syslog"), None); // syslog priority, not XML
        assert_eq!(XmlParser.sniff(b"{\"a\":1}"), None);
        assert_eq!(XmlParser.sniff(b"a,b,c\n1,2,3"), None);
    }

    #[test]
    fn claims_xml_extensions() {
        assert_eq!(XmlParser.extensions(), &["xml", "nessus"]);
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("scan.xml", b"zz").unwrap().id(), "xml");
        assert_eq!(reg.resolve("scan.nessus", b"zz").unwrap().id(), "xml");
        assert_eq!(reg.resolve("-", REPORT.as_bytes()).unwrap().id(), "xml");
    }
}
