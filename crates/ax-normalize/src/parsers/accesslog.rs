//! Combined / Common Log Format parser — nginx & Apache access logs.
//!
//! The NCSA Common Log Format is positional:
//! `host ident user [time] "request" status bytes`, and the Combined Format adds
//! `"referer" "user-agent"`. The bracketed time and the quoted request/referer/
//! user-agent are single fields even though they contain spaces, so we tokenize
//! with `[...]` and `"..."` treated as one token each (honoring `\"` escapes).
//!
//! The conventional `-` placeholder becomes `Null` (honest absence, never a fake
//! `0`); `status`/`bytes` are typed numeric; the request line is split into
//! `method`/`path`/`protocol`. Detected by its unmistakable
//! `[time] "request" <status> <bytes>` shape — it claims only the explicit
//! `.accesslog` extension (real access logs are generically named `*.log`).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct AccessLogParser;

/// Splits one access-log line into positional fields, treating a `[...]` group
/// and a `"..."` group (with `\"` / `\\` escapes) each as a single field.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        match chars.peek() {
            None => break,
            Some('[') => {
                chars.next();
                let mut s = String::new();
                for c in chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                    s.push(c);
                }
                tokens.push(s);
            }
            Some('"') => {
                chars.next();
                let mut s = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(esc) = chars.next() {
                                s.push(esc);
                            }
                        }
                        '"' => break,
                        _ => s.push(c),
                    }
                }
                tokens.push(s);
            }
            Some(_) => {
                let mut s = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ' ' {
                        break;
                    }
                    s.push(c);
                    chars.next();
                }
                tokens.push(s);
            }
        }
    }
    tokens
}

/// A `-` placeholder is honest absence; otherwise the raw string.
fn text_field(s: &str) -> Value {
    if s == "-" {
        Value::Null
    } else {
        Value::Str(s.to_string())
    }
}

/// A `-` placeholder is `Null`; otherwise type-inferred (so `status`/`bytes` are
/// numeric).
fn num_field(s: &str) -> Value {
    if s == "-" {
        Value::Null
    } else {
        infer::infer_scalar(s)
    }
}

impl AccessLogParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }

    /// Maps positional tokens to a named row. `tokens` is guaranteed `len >= 7`.
    fn row(tokens: &[String]) -> BTreeMap<String, Value> {
        let mut row = BTreeMap::new();
        row.insert("host".into(), text_field(&tokens[0]));
        row.insert("ident".into(), text_field(&tokens[1]));
        row.insert("user".into(), text_field(&tokens[2]));
        row.insert("time".into(), text_field(&tokens[3]));

        // Request line: "METHOD PATH PROTOCOL".
        let mut req = tokens[4].splitn(3, ' ');
        row.insert("method".into(), text_field(req.next().unwrap_or("-")));
        row.insert("path".into(), text_field(req.next().unwrap_or("-")));
        row.insert("protocol".into(), text_field(req.next().unwrap_or("-")));

        row.insert("status".into(), num_field(&tokens[5]));
        row.insert("bytes".into(), num_field(&tokens[6]));

        // Combined format adds referer and user-agent.
        if let Some(referer) = tokens.get(7) {
            row.insert("referer".into(), text_field(referer));
        }
        if let Some(ua) = tokens.get(8) {
            row.insert("user_agent".into(), text_field(ua));
        }
        row
    }
}

impl FormatParser for AccessLogParser {
    fn id(&self) -> &'static str {
        "accesslog"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["accesslog"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        // The bracketed time and quoted request are the signature; without them
        // a 7-token line is just whitespace-separated text, not an access log.
        if !line.contains('[') || !line.contains('"') {
            return None;
        }
        let tokens = tokenize(line);
        if tokens.len() < 7 {
            return None;
        }
        // A valid HTTP status sits at a fixed position only when the time and
        // request tokenized as single fields — so this also validates the shape.
        let status_ok = tokens[5]
            .parse::<u16>()
            .is_ok_and(|s| (100..=599).contains(&s));
        let bytes_ok = tokens[6] == "-" || tokens[6].parse::<u64>().is_ok();
        (status_ok && bytes_ok).then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let tokens = tokenize(line);
            if tokens.len() < 7 {
                return Err(self.err(format!(
                    "malformed access-log line: expected >= 7 fields, got {}",
                    tokens.len()
                )));
            }
            builder.push_row(Self::row(&tokens));
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const COMBINED: &str = "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \
\"GET /apache_pb.gif HTTP/1.0\" 200 2326 \
\"http://example.com/start.html\" \"Mozilla/4.08 [en] (Win98)\"\n";

    const COMMON: &str =
        "192.168.0.1 - - [10/Oct/2000:13:55:40 -0700] \"POST /login HTTP/1.1\" 302 -\n";

    fn parse(s: &str) -> Vec<Column> {
        AccessLogParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter().find(|c| c.name == name).unwrap()
    }

    #[test]
    fn parses_combined_fields() {
        let cols = parse(COMBINED);
        assert_eq!(col(&cols, "host").cells[0], Value::Str("127.0.0.1".into()));
        assert_eq!(col(&cols, "user").cells[0], Value::Str("frank".into()));
        assert_eq!(
            col(&cols, "time").cells[0],
            Value::Str("10/Oct/2000:13:55:36 -0700".into())
        );
        assert_eq!(col(&cols, "method").cells[0], Value::Str("GET".into()));
        assert_eq!(
            col(&cols, "path").cells[0],
            Value::Str("/apache_pb.gif".into())
        );
        assert_eq!(
            col(&cols, "protocol").cells[0],
            Value::Str("HTTP/1.0".into())
        );
        assert_eq!(col(&cols, "status").ty, ColType::Int);
        assert_eq!(col(&cols, "status").cells[0], Value::Int(200));
        assert_eq!(col(&cols, "bytes").cells[0], Value::Int(2326));
        assert_eq!(
            col(&cols, "referer").cells[0],
            Value::Str("http://example.com/start.html".into())
        );
        // The user-agent keeps its embedded brackets — they were inside quotes.
        assert_eq!(
            col(&cols, "user_agent").cells[0],
            Value::Str("Mozilla/4.08 [en] (Win98)".into())
        );
    }

    #[test]
    fn dash_placeholders_are_null() {
        let cols = parse(COMMON);
        assert_eq!(col(&cols, "ident").cells[0], Value::Null);
        assert_eq!(col(&cols, "user").cells[0], Value::Null);
        assert_eq!(col(&cols, "bytes").cells[0], Value::Null); // `-` bytes
        assert_eq!(col(&cols, "status").cells[0], Value::Int(302));
    }

    #[test]
    fn common_format_has_no_referer_or_ua_column() {
        let cols = parse(COMMON);
        assert!(cols.iter().all(|c| c.name != "referer"));
        assert!(cols.iter().all(|c| c.name != "user_agent"));
    }

    #[test]
    fn mixed_common_and_combined_pads_with_null() {
        // Combined first, then common: referer/ua exist but are null on row 1.
        let cols = parse(&format!("{COMBINED}{COMMON}"));
        let referer = col(&cols, "referer");
        assert_eq!(referer.cells.len(), 2);
        assert_eq!(referer.cells[1], Value::Null);
    }

    #[test]
    fn malformed_line_errors() {
        assert!(matches!(
            AccessLogParser.parse("-", b"this is not an access log\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn tokenize_groups_brackets_and_quotes() {
        let t = tokenize("a [x y] \"q \\\"r\\\" s\" b");
        assert_eq!(t, vec!["a", "x y", "q \"r\" s", "b"]);
    }

    #[test]
    fn sniff_recognizes_access_logs() {
        assert_eq!(AccessLogParser.sniff(COMBINED.as_bytes()), Some(STRONG));
        assert_eq!(AccessLogParser.sniff(COMMON.as_bytes()), Some(STRONG));
        // No bracket/quote signature → not an access log even with 7 tokens.
        assert_eq!(AccessLogParser.sniff(b"a b c d e 200 1024"), None);
        // BOTH a bracket and a quote are required: one alone is not the
        // signature, even when status/bytes are otherwise valid.
        assert_eq!(
            AccessLogParser.sniff(b"1.1.1.1 - - [t i] GET 200 10"),
            None,
            "bracket present but no quote"
        );
        assert_eq!(
            AccessLogParser.sniff(b"1.1.1.1 - - t \"GET / HTTP/1.1\" 200 10"),
            None,
            "quote present but no bracket"
        );
        assert_eq!(AccessLogParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
        assert_eq!(AccessLogParser.sniff(b"k=1 v=2"), None); // logfmt-ish
    }

    #[test]
    fn claims_the_accesslog_extension() {
        assert_eq!(AccessLogParser.extensions(), &["accesslog"]);
    }

    #[test]
    fn sniff_rejects_out_of_range_status_and_bad_bytes() {
        // status 99 (< 100) and 600 (> 599) are not HTTP statuses.
        let lo = "1.1.1.1 - - [t i] \"GET / HTTP/1.1\" 99 10\n";
        let hi = "1.1.1.1 - - [t i] \"GET / HTTP/1.1\" 600 10\n";
        let bad_bytes = "1.1.1.1 - - [t i] \"GET / HTTP/1.1\" 200 abc\n";
        assert_eq!(AccessLogParser.sniff(lo.as_bytes()), None);
        assert_eq!(AccessLogParser.sniff(hi.as_bytes()), None);
        assert_eq!(AccessLogParser.sniff(bad_bytes.as_bytes()), None);
        // Boundaries 100 and 599 are valid.
        let edge_lo = "1.1.1.1 - - [t i] \"GET / HTTP/1.1\" 100 10\n";
        let edge_hi = "1.1.1.1 - - [t i] \"GET / HTTP/1.1\" 599 10\n";
        assert_eq!(AccessLogParser.sniff(edge_lo.as_bytes()), Some(STRONG));
        assert_eq!(AccessLogParser.sniff(edge_hi.as_bytes()), Some(STRONG));
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(
            reg.resolve("x.accesslog", COMMON.as_bytes()).unwrap().id(),
            "accesslog"
        );
        // A `.log` file with access-log content routes by sniff.
        assert_eq!(
            reg.resolve("access.log", COMBINED.as_bytes()).unwrap().id(),
            "accesslog"
        );
        // A non-access `.log` is not hijacked.
        assert_eq!(reg.resolve("app.log", b"a,b\n1,2").unwrap().id(), "csv");
    }
}
