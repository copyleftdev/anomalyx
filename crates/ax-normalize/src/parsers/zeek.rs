//! Zeek (Bro) TSV log parser — `conn.log`, `dns.log`, and the rest of the family.
//!
//! Zeek logs are tab-separated with a `#`-prefixed metadata header that declares
//! the field separator (`#separator`), the column names (`#fields`), and the
//! token used for unset values (`#unset_field`, default `-`). We honor those
//! directives and map the unset token to `Null`. Detected by its unmistakable
//! `#separator` header, so it claims no file extension (Zeek logs are generically
//! named `*.log`, which we don't want to hijack).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use ax_core::{AxError, Column, Value};

#[derive(Debug, Default, Clone)]
pub struct ZeekParser;

/// Decodes a Zeek `#separator` value such as `\x09` into its character. A plain
/// character (or unescaped byte) is returned as-is.
fn decode_separator(token: &str) -> Option<char> {
    match token.strip_prefix("\\x") {
        Some(hex) => u8::from_str_radix(hex, 16).ok().map(|b| b as char),
        None => token.chars().next(),
    }
}

impl ZeekParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for ZeekParser {
    fn id(&self) -> &'static str {
        "zeek"
    }
    fn extensions(&self) -> &'static [&'static str] {
        // No extension: Zeek logs are `*.log`, too generic to claim. Detection
        // is by the `#separator` header (see `sniff`).
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        text.trim_start()
            .starts_with("#separator")
            .then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut sep = '\t';
        let mut unset = "-".to_string();
        let mut empty = "(empty)".to_string();
        let mut fields: Option<Vec<String>> = None;
        let mut cols: Vec<Vec<Value>> = Vec::new();

        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix('#') {
                // `#separator` is space-delimited and comes first; it sets the
                // separator the rest of the header and the data rows use.
                if let Some(val) = rest.strip_prefix("separator") {
                    if let Some(c) = decode_separator(val.trim()) {
                        sep = c;
                    }
                    continue;
                }
                let mut parts = rest.split(sep);
                match parts.next().unwrap_or("") {
                    "fields" => {
                        let names: Vec<String> = parts.map(str::to_string).collect();
                        cols = vec![Vec::new(); names.len()];
                        fields = Some(names);
                    }
                    "unset_field" => {
                        if let Some(v) = parts.next() {
                            unset = v.to_string();
                        }
                    }
                    "empty_field" => {
                        if let Some(v) = parts.next() {
                            empty = v.to_string();
                        }
                    }
                    _ => {} // set_separator, types, path, open, close — ignored
                }
                continue;
            }

            // A data row. It must come after the `#fields` header.
            if fields.is_none() {
                return Err(self.err("data row before #fields header"));
            }
            let mut values = line.split(sep);
            for col in cols.iter_mut() {
                col.push(match values.next() {
                    Some(v) if v == unset => Value::Null,
                    Some(v) if v == empty => Value::Str(String::new()),
                    Some(v) => infer::infer_scalar(v),
                    None => Value::Null,
                });
            }
        }

        let names = fields.ok_or_else(|| self.err("missing #fields header"))?;
        Ok(names
            .into_iter()
            .zip(cols)
            .map(|(name, cells)| Column::new(name, cells))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    // A realistic conn.log slice: literal `\x09` separator directive, real tabs
    // elsewhere, and `-` for unset fields (service/duration on the second row).
    const CONN: &str = "#separator \\x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#path\tconn\n\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tproto\tservice\tduration\torig_bytes\n\
#types\ttime\tstring\taddr\tport\tenum\tstring\tinterval\tcount\n\
1300475167.096535\tCwx1\t192.168.1.1\t80\ttcp\thttp\t0.512\t1024\n\
1300475168.000000\tCwy2\t10.0.0.2\t443\ttcp\t-\t-\t-\n\
#close\t2011-03-18-19-06-08\n";

    fn parse(s: &str) -> Vec<Column> {
        ZeekParser.parse("conn.log", s.as_bytes()).unwrap()
    }

    #[test]
    fn separator_directive_decodes() {
        assert_eq!(decode_separator("\\x09"), Some('\t'));
        assert_eq!(decode_separator("\\x2c"), Some(','));
        assert_eq!(decode_separator(","), Some(','));
        assert_eq!(decode_separator(""), None);
    }

    #[test]
    fn parses_fields_and_typed_columns() {
        let cols = parse(CONN);
        let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "ts",
                "uid",
                "id.orig_h",
                "id.orig_p",
                "proto",
                "service",
                "duration",
                "orig_bytes"
            ]
        );
        assert_eq!(cols[0].len(), 2, "two data rows");
        assert_eq!(cols[0].ty, ColType::Float, "ts is epoch float");
        assert_eq!(cols[3].ty, ColType::Int, "ports are ints");
        assert_eq!(cols[1].ty, ColType::Str, "uid is string");
    }

    #[test]
    fn unset_token_maps_to_null() {
        let cols = parse(CONN);
        let service = cols.iter().find(|c| c.name == "service").unwrap();
        // row 0 "http", row 1 "-" (unset) → exactly one null
        assert_eq!(service.null_count(), 1);
        assert_eq!(service.cells[0], Value::Str("http".into()));
        assert_eq!(service.cells[1], Value::Null);
        // the comment header lines are not data
        assert_eq!(
            cols.iter()
                .find(|c| c.name == "duration")
                .unwrap()
                .null_count(),
            1
        );
    }

    #[test]
    fn respects_a_custom_unset_field() {
        let s = "#separator \\x09\n#unset_field\tNULL\n#fields\ta\tb\n1\tNULL\n";
        let cols = ZeekParser.parse("-", s.as_bytes()).unwrap();
        assert_eq!(cols[1].cells[0], Value::Null);
    }

    #[test]
    fn respects_a_custom_empty_field() {
        // A non-default empty token maps to an empty string (distinct from unset
        // → Null). Uses a custom token so the directive is actually observed.
        let s = "#separator \\x09\n#empty_field\tEMPTY\n#unset_field\t-\n#fields\ta\tb\n1\tEMPTY\n2\t-\n";
        let cols = ZeekParser.parse("-", s.as_bytes()).unwrap();
        assert_eq!(
            cols[1].cells[0],
            Value::Str(String::new()),
            "empty token → empty string"
        );
        assert_eq!(cols[1].cells[1], Value::Null, "unset token → null");
    }

    #[test]
    fn sniff_recognizes_zeek_header_only() {
        assert_eq!(ZeekParser.sniff(CONN.as_bytes()), Some(STRONG));
        assert_eq!(ZeekParser.sniff(b"a,b\n1,2"), None);
        assert_eq!(ZeekParser.sniff(b"ts\tuid\n1\tx"), None); // plain TSV is not Zeek
    }

    #[test]
    fn claims_no_extension() {
        assert!(ZeekParser.extensions().is_empty());
    }

    #[test]
    fn data_before_fields_errors() {
        assert!(matches!(
            ZeekParser.parse("-", b"1\t2\t3\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn header_without_fields_errors() {
        assert!(matches!(
            ZeekParser.parse("-", b"#separator \\x09\n#path\tconn\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn resolves_by_content_not_extension() {
        let reg = crate::parser::ParserRegistry::default();
        // a Zeek body wins by sniff even though `.log` claims no parser
        assert_eq!(
            reg.resolve("conn.log", CONN.as_bytes()).unwrap().id(),
            "zeek"
        );
        // a non-Zeek `.log` is NOT hijacked by the zeek parser
        assert_eq!(reg.resolve("app.log", b"a,b\n1,2").unwrap().id(), "csv");
    }
}
