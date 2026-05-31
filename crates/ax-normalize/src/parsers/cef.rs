//! CEF and LEEF parsers — ArcSight / QRadar SIEM event formats.
//!
//! Both are pipe-delimited headers followed by a `key=value` extension. One row
//! per event; the header's category fields (`signatureId`/`name` for CEF,
//! `eventId` for LEEF) and `severity` are exactly what `dist.chi2` reads as a
//! signature/category mix shift, and a value never seen in the baseline surfaces
//! as a new category automatically.
//!
//! - **CEF** (`CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|ext`):
//!   7 header fields (with `\|` / `\\` escaping) then a space-separated extension
//!   whose values may contain spaces — split at ` key=` boundaries, with
//!   `\=` / `\\` / `\n` value escaping.
//! - **LEEF** (`LEEF:Version|Vendor|Product|Version|EventID|[Delimiter|]ext`):
//!   5 header fields; LEEF 2.0 adds an explicit delimiter field (a char or `xHH`
//!   hex), LEEF 1.0 uses a tab. The extension is plain `key=value` pairs.

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// Decodes the SIEM backslash escapes: `\n`/`\r`/`\t` to whitespace, and any
/// other `\x` (e.g. `\|`, `\=`, `\\`) to the literal `x`.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Splits on `|` that is not backslash-escaped, into at most `max` fields (the
/// last absorbs any remaining pipes). Escape pairs are preserved for [`unescape`].
fn split_unescaped_pipe(s: &str, max: usize) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push('\\');
            if let Some(next) = chars.next() {
                cur.push(next);
            }
        } else if c == '|' && fields.len() < max - 1 {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    fields.push(cur);
    fields
}

/// Parses a CEF extension (`key=value key2=value2 ...`) where a value may itself
/// contain spaces — a new key begins only at a space-preceded `ident=`. Values
/// are unescaped.
fn parse_cef_extension(ext: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = ext.chars().collect();
    let n = chars.len();
    // Locate each key: an identifier run, ending in `=`, at start or after a space.
    let mut keys: Vec<(usize, usize)> = Vec::new(); // (key_start, eq_index)
    let mut i = 0;
    while i < n {
        if (i == 0 || chars[i - 1] == ' ') && is_ident(chars[i]) {
            let mut j = i;
            while j < n && is_ident(chars[j]) {
                j += 1;
            }
            if j < n && chars[j] == '=' {
                keys.push((i, j));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    let mut pairs = Vec::new();
    for (idx, &(key_start, eq)) in keys.iter().enumerate() {
        let key: String = chars[key_start..eq].iter().collect();
        let value_end = keys.get(idx + 1).map_or(n, |&(next_start, _)| next_start);
        let raw: String = chars[eq + 1..value_end].iter().collect();
        pairs.push((key, unescape(raw.trim_end())));
    }
    pairs
}

/// Resolves a LEEF 2.0 delimiter spec: a literal char, or `xHH` / `\xHH` hex.
/// Defaults to tab (the LEEF 1.0 separator).
fn leef_delimiter(spec: &str) -> char {
    if let Some(hex) = spec.strip_prefix('x').or_else(|| spec.strip_prefix("\\x")) {
        if let Ok(byte) = u8::from_str_radix(hex, 16) {
            return byte as char;
        }
    }
    spec.chars().next().unwrap_or('\t')
}

// ----------------------------------------------------------------- CEF --------

#[derive(Debug, Default, Clone)]
pub struct CefParser;

const CEF_HEADER: [&str; 7] = [
    "cefVersion",
    "deviceVendor",
    "deviceProduct",
    "deviceVersion",
    "signatureId",
    "name",
    "severity",
];

impl CefParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for CefParser {
    fn id(&self) -> &'static str {
        "cef"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cef"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        line.starts_with("CEF:").then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let rest = line
                .strip_prefix("CEF:")
                .ok_or_else(|| self.err("not a CEF line: missing 'CEF:' prefix"))?;
            let fields = split_unescaped_pipe(rest, 8);
            if fields.len() < CEF_HEADER.len() {
                return Err(self.err("CEF header requires 7 pipe-delimited fields"));
            }
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for (name, raw) in CEF_HEADER.iter().zip(&fields) {
                let decoded = unescape(raw);
                // Severity is the analyzable numeric (or a named level); the rest
                // are categorical identifiers kept verbatim.
                let cell = if *name == "severity" {
                    infer::infer_scalar(&decoded)
                } else {
                    Value::Str(decoded)
                };
                row.insert((*name).to_string(), cell);
            }
            if let Some(ext) = fields.get(CEF_HEADER.len()) {
                for (key, value) in parse_cef_extension(ext) {
                    row.insert(key, infer::infer_scalar(&value));
                }
            }
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

// ---------------------------------------------------------------- LEEF --------

#[derive(Debug, Default, Clone)]
pub struct LeefParser;

const LEEF_HEADER: [&str; 5] = [
    "leefVersion",
    "vendor",
    "product",
    "productVersion",
    "eventId",
];

impl LeefParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for LeefParser {
    fn id(&self) -> &'static str {
        "leef"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["leef"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        line.starts_with("LEEF:").then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let rest = line
                .strip_prefix("LEEF:")
                .ok_or_else(|| self.err("not a LEEF line: missing 'LEEF:' prefix"))?;
            // LEEF 2.0 inserts a delimiter field between the header and extension.
            let version = rest.split('|').next().unwrap_or("");
            let is_v2 = version.starts_with('2');
            let header_count = LEEF_HEADER.len() + usize::from(is_v2);
            let parts: Vec<&str> = rest.splitn(header_count + 1, '|').collect();
            if parts.len() < LEEF_HEADER.len() {
                return Err(self.err("LEEF header requires at least 5 fields"));
            }
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for (name, value) in LEEF_HEADER.iter().zip(&parts) {
                row.insert((*name).to_string(), Value::Str((*value).to_string()));
            }
            let delimiter = if is_v2 {
                parts
                    .get(LEEF_HEADER.len())
                    .map_or('\t', |s| leef_delimiter(s))
            } else {
                '\t'
            };
            if let Some(ext) = parts.get(header_count) {
                for token in ext.split(delimiter) {
                    if let Some((key, value)) = token.split_once('=') {
                        if !key.is_empty() {
                            row.insert(key.to_string(), infer::infer_scalar(value));
                        }
                    }
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

    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    // -------------------------------------------------------- helpers --------

    #[test]
    fn unescape_decodes_siem_escapes() {
        assert_eq!(unescape(r"a\|b"), "a|b");
        assert_eq!(unescape(r"a\=b"), "a=b");
        assert_eq!(unescape(r"a\\b"), r"a\b");
        assert_eq!(unescape(r"a\nb"), "a\nb");
        assert_eq!(unescape("plain"), "plain");
    }

    #[test]
    fn split_unescaped_pipe_keeps_escaped_and_extra() {
        // Escaped pipe stays in its field; once 8 fields are reached the last
        // absorbs any further pipes (9 segments here → 8th keeps "i|j").
        let f = split_unescaped_pipe(r"a\|b|c|d|e|f|g|h|i|j", 8);
        assert_eq!(f.len(), 8);
        assert_eq!(f[0], r"a\|b", "escaped pipe is not a separator");
        assert_eq!(f[7], "i|j", "extension field absorbs extra pipes");
    }

    #[test]
    fn parse_cef_extension_handles_spaces_and_escapes() {
        let pairs = parse_cef_extension(r"src=10.0.0.1 msg=worm was stopped spt=1232 note=a\=b");
        assert_eq!(
            pairs,
            vec![
                ("src".into(), "10.0.0.1".into()),
                ("msg".into(), "worm was stopped".into()), // value with spaces
                ("spt".into(), "1232".into()),
                ("note".into(), "a=b".into()), // escaped '='
            ]
        );
    }

    #[test]
    fn parse_cef_extension_only_breaks_at_space_preceded_keys() {
        // A `=` that is not space-preceded stays inside the value (a new key
        // begins ONLY after a space). And single-char keys advance correctly.
        assert_eq!(
            parse_cef_extension("k=ab=cd"),
            vec![("k".into(), "ab=cd".into())]
        );
        assert_eq!(
            parse_cef_extension("a=1 b=2"),
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn leef_delimiter_resolves_char_hex_and_default() {
        assert_eq!(leef_delimiter("^"), '^');
        assert_eq!(leef_delimiter("x09"), '\t');
        assert_eq!(leef_delimiter(r"\x09"), '\t');
        assert_eq!(leef_delimiter(""), '\t'); // empty → tab default
    }

    // ----------------------------------------------------------- CEF --------

    const CEF: &str = concat!(
        r"CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1 spt=1232 msg=took action",
        "\n",
        r"CEF:0|Security|threatmanager|1.0|200|port scan|3|src=10.0.0.9 dst=2.1.2.2",
        "\n",
    );

    fn cef(s: &str) -> Vec<Column> {
        CefParser.parse("-", s.as_bytes()).unwrap()
    }

    #[test]
    fn cef_header_fields() {
        let cols = cef(CEF);
        assert_eq!(
            col(&cols, "deviceProduct").cells[0],
            Value::Str("threatmanager".into())
        );
        assert_eq!(col(&cols, "signatureId").cells[0], Value::Str("100".into()));
        assert_eq!(col(&cols, "name").cells[1], Value::Str("port scan".into()));
        let sev = col(&cols, "severity");
        assert_eq!(sev.ty, ColType::Int, "severity is the analyzable numeric");
        assert_eq!(sev.cells, vec![Value::Int(10), Value::Int(3)]);
    }

    #[test]
    fn cef_extension_fields_typed_and_padded() {
        let cols = cef(CEF);
        assert_eq!(col(&cols, "src").cells[0], Value::Str("10.0.0.1".into()));
        assert_eq!(col(&cols, "spt").cells[0], Value::Int(1232)); // port → int
        assert_eq!(col(&cols, "msg").cells[0], Value::Str("took action".into()));
        // dst only on the second event; spt/msg only on the first.
        assert_eq!(col(&cols, "dst").cells[0], Value::Null);
        assert_eq!(col(&cols, "spt").cells[1], Value::Null);
    }

    #[test]
    fn cef_escaped_pipe_in_header() {
        let cols = cef(r"CEF:0|Sec\|ops|prod|1|1|n|5|");
        assert_eq!(
            col(&cols, "deviceVendor").cells[0],
            Value::Str("Sec|ops".into())
        );
    }

    #[test]
    fn cef_without_extension() {
        let cols = cef("CEF:0|v|p|1.0|42|evt|7\n"); // 7 fields, no extension
        assert_eq!(col(&cols, "signatureId").cells[0], Value::Str("42".into()));
        assert_eq!(col(&cols, "severity").cells[0], Value::Int(7));
    }

    #[test]
    fn cef_malformed_too_few_fields_errors() {
        assert!(matches!(
            CefParser.parse("-", b"CEF:0|only|three\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            CefParser.parse("-", b"not a cef line\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn cef_sniff_and_resolution() {
        assert_eq!(CefParser.sniff(CEF.as_bytes()), Some(STRONG));
        assert_eq!(CefParser.sniff(b"LEEF:1.0|v|p|1|x|"), None);
        assert_eq!(CefParser.sniff(b"a,b,c\n1,2,3"), None);
        assert_eq!(CefParser.extensions(), &["cef"]);
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("e.cef", b"x").unwrap().id(), "cef");
        assert_eq!(reg.resolve("-", CEF.as_bytes()).unwrap().id(), "cef");
    }

    // ---------------------------------------------------------- LEEF --------

    #[test]
    fn leef_v1_tab_extension() {
        let line = "LEEF:1.0|Lancope|StealthWatch|1.0|41|src=192.0.2.0\tdst=172.50.123.1\tsev=5\n";
        let cols = LeefParser.parse("-", line.as_bytes()).unwrap();
        assert_eq!(col(&cols, "leefVersion").cells[0], Value::Str("1.0".into()));
        assert_eq!(col(&cols, "vendor").cells[0], Value::Str("Lancope".into()));
        assert_eq!(col(&cols, "eventId").cells[0], Value::Str("41".into()));
        assert_eq!(col(&cols, "src").cells[0], Value::Str("192.0.2.0".into()));
        assert_eq!(col(&cols, "sev").cells[0], Value::Int(5));
    }

    #[test]
    fn leef_header_only_no_extension() {
        // Exactly 5 fields (no extension) is valid LEEF 1.0 — pins the `< 5`
        // header-count boundary (must not reject a 5-field header).
        let cols = LeefParser.parse("-", b"LEEF:1.0|Acme|Tool|2|77").unwrap();
        assert_eq!(col(&cols, "eventId").cells[0], Value::Str("77".into()));
        assert_eq!(col(&cols, "vendor").cells[0], Value::Str("Acme".into()));
    }

    #[test]
    fn leef_v2_explicit_delimiter() {
        // LEEF 2.0 with a '^' delimiter field between header and extension.
        let line = "LEEF:2.0|Vendor|Product|2.5|1001|^|src=10.0.0.1^dst=10.0.0.2^spt=22\n";
        let cols = LeefParser.parse("-", line.as_bytes()).unwrap();
        assert_eq!(col(&cols, "eventId").cells[0], Value::Str("1001".into()));
        assert_eq!(col(&cols, "src").cells[0], Value::Str("10.0.0.1".into()));
        assert_eq!(col(&cols, "spt").cells[0], Value::Int(22));
        // The delimiter field itself is not a data column.
        assert!(cols.iter().all(|c| c.name != "^"));
    }

    #[test]
    fn leef_v2_hex_delimiter() {
        // x09 = tab delimiter.
        let line = "LEEF:2.0|V|P|1|99|x09|a=1\tb=2\n";
        let cols = LeefParser.parse("-", line.as_bytes()).unwrap();
        assert_eq!(col(&cols, "a").cells[0], Value::Int(1));
        assert_eq!(col(&cols, "b").cells[0], Value::Int(2));
    }

    #[test]
    fn leef_malformed_and_sniff() {
        assert!(matches!(
            LeefParser.parse("-", b"LEEF:1.0|onlytwo\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            LeefParser.parse("-", b"not leef\n"),
            Err(AxError::Parse { .. })
        ));
        assert_eq!(LeefParser.sniff(b"LEEF:1.0|v|p|1|x|a=1"), Some(STRONG));
        assert_eq!(LeefParser.sniff(b"CEF:0|v|p|1|1|n|5|"), None);
        assert_eq!(LeefParser.extensions(), &["leef"]);
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("e.leef", b"x").unwrap().id(), "leef");
        assert_eq!(
            reg.resolve("-", b"LEEF:1.0|v|p|1|x|a=1\n").unwrap().id(),
            "leef"
        );
    }
}
