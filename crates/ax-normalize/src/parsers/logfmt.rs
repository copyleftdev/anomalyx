//! logfmt parser — `key=value` structured logs (Heroku, Go `log/slog`, Grafana).
//!
//! Each line is one record: space-separated `key=value` pairs. Values may be
//! bare (type-inferred) or double-quoted (always a string, with `\"` / `\\`
//! escapes). A bare key with no `=` is a boolean flag (`true`); `key=` with an
//! empty value is `Null`. Records are unioned into columns like NDJSON, so
//! missing keys become `Null`.

use crate::infer;
use crate::parser::{Confidence, FormatParser, TEXT};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct LogfmtParser;

/// A `key`-shaped token: non-empty, starting with a letter or `_`, made of
/// `[A-Za-z0-9_.-]`. Used both to parse and to sniff.
fn is_key(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Parses one logfmt line into typed key→value pairs.
fn parse_line(line: &str) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        // Read the key up to '=' or a space.
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ' ' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.peek() == Some(&'=') {
            chars.next(); // consume '='
            let value = if chars.peek() == Some(&'"') {
                chars.next(); // opening quote
                let mut s = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(esc) = chars.next() {
                                s.push(esc); // \" -> ", \\ -> \
                            }
                        }
                        '"' => break,
                        _ => s.push(c),
                    }
                }
                Value::Str(s) // quoted values are always strings
            } else {
                let mut raw = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ' ' {
                        break;
                    }
                    raw.push(c);
                    chars.next();
                }
                if raw.is_empty() {
                    Value::Null // `key=` with no value
                } else {
                    infer::infer_scalar(&raw)
                }
            };
            out.insert(key, value);
        } else {
            // Bare key with no '=' is a boolean flag.
            out.insert(key, Value::Bool(true));
        }
    }
    out
}

impl FormatParser for LogfmtParser {
    fn id(&self) -> &'static str {
        "logfmt"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["logfmt"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        // logfmt records have several space-separated fields, most of which are
        // `key=value`. Require ≥2 tokens and a key=value majority — that keeps it
        // from claiming CSV/plain text.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            return None;
        }
        let kv = tokens
            .iter()
            .filter(|t| matches!(t.split_once('='), Some((k, _)) if is_key(k)))
            .count();
        (kv >= 1 && kv * 2 >= tokens.len()).then_some(TEXT)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| AxError::Parse {
            format: self.id().to_string(),
            message: e.to_string(),
        })?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            builder.push_row(parse_line(line));
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const LOG: &str = "level=info msg=\"request handled\" status=200 dur=0.123 ok=true\n\
level=error msg=\"db timeout\" status=500 retries=3\n";

    fn parse(s: &str) -> Vec<Column> {
        LogfmtParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn parses_typed_values() {
        let cols = parse(LOG);
        assert_eq!(col(&cols, "status").ty, ColType::Int);
        assert_eq!(col(&cols, "dur").ty, ColType::Float);
        assert_eq!(col(&cols, "level").ty, ColType::Str);
        assert_eq!(col(&cols, "ok").cells[0], Value::Bool(true));
    }

    #[test]
    fn quoted_values_are_strings_with_spaces() {
        let cols = parse(LOG);
        assert_eq!(
            col(&cols, "msg").cells[0],
            Value::Str("request handled".into())
        );
        assert_eq!(col(&cols, "msg").cells[1], Value::Str("db timeout".into()));
    }

    #[test]
    fn missing_keys_pad_with_null() {
        // `retries` only appears on the second line; `dur`/`ok` only on the first.
        let cols = parse(LOG);
        assert_eq!(col(&cols, "retries").cells[0], Value::Null);
        assert_eq!(col(&cols, "retries").cells[1], Value::Int(3));
        assert_eq!(col(&cols, "dur").null_count(), 1);
    }

    #[test]
    fn quote_escapes() {
        let cols = parse("msg=\"say \\\"hi\\\" now\" path=\"a\\\\b\"\n");
        assert_eq!(
            col(&cols, "msg").cells[0],
            Value::Str("say \"hi\" now".into())
        );
        assert_eq!(col(&cols, "path").cells[0], Value::Str("a\\b".into()));
    }

    #[test]
    fn bare_flag_and_empty_value() {
        let cols = parse("debug status= name=x\n");
        assert_eq!(col(&cols, "debug").cells[0], Value::Bool(true));
        assert_eq!(col(&cols, "status").cells[0], Value::Null); // `status=` → null
        assert_eq!(col(&cols, "name").cells[0], Value::Str("x".into()));
    }

    #[test]
    fn is_key_classification() {
        assert!(is_key("level"));
        assert!(is_key("id.orig_h"));
        assert!(is_key("_x-1"));
        assert!(!is_key("1abc")); // must start alpha/_
        assert!(!is_key("")); // empty
        assert!(!is_key("a b")); // space not allowed
    }

    #[test]
    fn sniff_recognizes_logfmt() {
        assert_eq!(LogfmtParser.sniff(LOG.as_bytes()), Some(TEXT));
        // Exactly 2 tokens, both key=value, is accepted (boundary: len >= 2).
        assert_eq!(LogfmtParser.sniff(b"level=info status=200"), Some(TEXT));
        // 1 key=value among 3 tokens fails the majority (kv*2 >= len): a mostly
        // prose line must not be claimed as logfmt.
        assert_eq!(LogfmtParser.sniff(b"a=1 b c"), None);
        assert_eq!(LogfmtParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
        assert_eq!(LogfmtParser.sniff(b"just some prose words"), None); // no key=value
        assert_eq!(LogfmtParser.sniff(b"single=token"), None); // <2 tokens
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("app.logfmt", b"x").unwrap().id(), "logfmt");
        assert_eq!(
            reg.resolve("app.log", LOG.as_bytes()).unwrap().id(),
            "logfmt",
            "content sniff wins for a .log file"
        );
    }
}
