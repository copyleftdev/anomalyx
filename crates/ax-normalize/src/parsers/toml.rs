//! TOML and INI config parsers — config drift between environments.
//!
//! Both collapse a config into a **single row** whose columns are the config's
//! keys, so `struct.schema --baseline` reads two configs as schemas and surfaces
//! unexpected/added/removed keys and type changes — the drift use case.
//!
//! - **TOML** is parsed with the `toml` crate into a `toml::Value`, converted to
//!   a `serde_json::Value`, and lowered through the same union-key path as JSON
//!   (nested tables become their canonical JSON string, exactly like JSON/YAML).
//! - **INI** is hand-rolled: `[section]` headers namespace keys (`section.key`),
//!   `key = value` / `key : value` lines are type-inferred, `;`/`#` lines are
//!   comments. INI accepts bare (unquoted) values that TOML rejects, which keeps
//!   the two formats cleanly separable.

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG, TEXT};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

// ---------------------------------------------------------------- TOML --------

#[derive(Debug, Default, Clone)]
pub struct TomlParser;

/// Converts a `toml::Value` into the equivalent `serde_json::Value`. Datetimes
/// become their canonical string (deterministic, no wall-clock); non-finite
/// floats become `Null` since they cannot enter a deterministic reduction.
fn toml_to_json(v: toml::Value) -> serde_json::Value {
    use serde_json::Value as J;
    use toml::Value as T;
    match v {
        T::String(s) => J::String(s),
        T::Integer(i) => J::Number(i.into()),
        T::Float(f) => serde_json::Number::from_f64(f).map_or(J::Null, J::Number),
        T::Boolean(b) => J::Bool(b),
        T::Datetime(dt) => J::String(dt.to_string()),
        T::Array(a) => J::Array(a.into_iter().map(toml_to_json).collect()),
        T::Table(t) => J::Object(t.into_iter().map(|(k, v)| (k, toml_to_json(v))).collect()),
    }
}

impl TomlParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for TomlParser {
    fn id(&self) -> &'static str {
        "toml"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["toml"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        // Confirm by parsing: TOML's top level is always a table, and we require
        // at least one key so an empty/comment-only file is not claimed. This
        // cleanly rejects a JSON array (`[1,2,3]` is not a valid TOML document).
        let parsed = toml::from_str::<toml::Value>(text).ok()?;
        let nonempty = parsed.as_table().is_some_and(|t| !t.is_empty());
        nonempty.then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let value = toml::from_str::<toml::Value>(text).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        builder.push_value(toml_to_json(value));
        Ok(builder.finish())
    }
}

// ----------------------------------------------------------------- INI --------

#[derive(Debug, Default, Clone)]
pub struct IniParser;

/// A `;`- or `#`-introduced comment line.
fn ini_is_comment(line: &str) -> bool {
    line.starts_with(';') || line.starts_with('#')
}

/// A `[section]` header (non-empty inner name).
fn ini_is_section(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']') && line.len() > 2
}

/// Splits a `key = value` / `key : value` line at the first `=` or `:`. `None`
/// if there is no separator or the key is empty. Section lines are handled
/// before this, so a `[a:b]` line never reaches here as a key/value.
fn ini_kv_split(line: &str) -> Option<(&str, &str)> {
    let i = line.find(['=', ':'])?;
    let key = line[..i].trim();
    (!key.is_empty()).then_some((key, &line[i + 1..]))
}

/// A quoted INI value is a verbatim string; otherwise it is type-inferred.
fn parse_ini_value(raw: &str) -> Value {
    let quoted = raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')));
    if quoted {
        Value::Str(raw[1..raw.len() - 1].to_string())
    } else {
        infer::infer_scalar(raw)
    }
}

impl IniParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for IniParser {
    fn id(&self) -> &'static str {
        "ini"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ini", "cfg", "conf"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut first: Option<&str> = None;
        let mut has_section = false;
        let mut has_kv = false;
        for raw in text.lines() {
            let l = raw.trim();
            if l.is_empty() || ini_is_comment(l) {
                continue;
            }
            if first.is_none() {
                first = Some(l);
            }
            if ini_is_section(l) {
                has_section = true;
            } else if ini_kv_split(l).is_some() {
                has_kv = true;
            }
        }
        let first = first?;
        if has_section && has_kv {
            // A `[section]` plus a `key = value` is unmistakably an INI config —
            // strong enough to win a bare `[...]` line away from JSON.
            return Some(STRONG);
        }
        (ini_is_section(first) || ini_kv_split(first).is_some()).then_some(TEXT)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut section = String::new();
        let mut row: BTreeMap<String, Value> = BTreeMap::new();
        for raw in text.lines() {
            let l = raw.trim();
            if l.is_empty() || ini_is_comment(l) {
                continue;
            }
            if ini_is_section(l) {
                section = l[1..l.len() - 1].trim().to_string();
                continue;
            }
            match ini_kv_split(l) {
                Some((key, val)) => {
                    let column = if section.is_empty() {
                        key.to_string()
                    } else {
                        format!("{section}.{key}")
                    };
                    row.insert(column, parse_ini_value(val.trim()));
                }
                None => return Err(self.err(format!("malformed INI line: {l}"))),
            }
        }
        let mut builder = TableBuilder::new();
        builder.push_row(row);
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

    // ------------------------------------------------------------ TOML -------

    const CONFIG: &str = r#"
title = "anomalyx"
retries = 3
ratio = 0.5
enabled = true
notanum = nan
tags = ["a", "b"]
created = 2024-01-02T03:04:05Z

[server]
host = "localhost"
port = 8080
"#;

    fn toml_parse(s: &str) -> Vec<Column> {
        TomlParser.parse("-", s.as_bytes()).unwrap()
    }

    #[test]
    fn toml_typed_scalars() {
        let cols = toml_parse(CONFIG);
        assert_eq!(col(&cols, "title").cells[0], Value::Str("anomalyx".into()));
        assert_eq!(col(&cols, "retries").ty, ColType::Int);
        assert_eq!(col(&cols, "retries").cells[0], Value::Int(3));
        assert_eq!(col(&cols, "ratio").cells[0], Value::Float(0.5));
        assert_eq!(col(&cols, "enabled").cells[0], Value::Bool(true));
        // A non-finite float cannot enter a reduction → honest Null.
        assert_eq!(col(&cols, "notanum").cells[0], Value::Null);
    }

    #[test]
    fn toml_datetime_array_and_nested_table_are_strings() {
        let cols = toml_parse(CONFIG);
        // Datetime → canonical string.
        match &col(&cols, "created").cells[0] {
            Value::Str(s) => assert!(s.contains("2024-01-02"), "got {s}"),
            other => panic!("expected Str datetime, got {other:?}"),
        }
        // Array → canonical JSON string.
        assert_eq!(
            col(&cols, "tags").cells[0],
            Value::Str("[\"a\",\"b\"]".into())
        );
        // Nested table → canonical JSON string (sorted keys, deterministic).
        assert_eq!(
            col(&cols, "server").cells[0],
            Value::Str("{\"host\":\"localhost\",\"port\":8080}".into())
        );
    }

    #[test]
    fn toml_is_a_single_row() {
        assert_eq!(col(&toml_parse(CONFIG), "title").cells.len(), 1);
    }

    #[test]
    fn toml_sniff_confirms_by_parsing() {
        assert_eq!(TomlParser.sniff(CONFIG.as_bytes()), Some(STRONG));
        assert_eq!(TomlParser.sniff(b"key = \"v\"\n"), Some(STRONG));
        assert_eq!(TomlParser.sniff(b"key=1\n"), Some(STRONG)); // valid TOML, no spaces
                                                                // Not claimed: empty / comment-only (empty table), and non-TOML shapes.
        assert_eq!(TomlParser.sniff(b""), None);
        assert_eq!(TomlParser.sniff(b"# just a comment\n"), None);
        assert_eq!(TomlParser.sniff(b"[1,2,3]"), None); // JSON array, not a TOML table
        assert_eq!(TomlParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
        assert_eq!(TomlParser.sniff(b"k=1 v=2\n"), None); // logfmt
        assert_eq!(TomlParser.sniff(b"kind: Pod\n"), None); // YAML
    }

    #[test]
    fn toml_malformed_errors() {
        assert!(matches!(
            TomlParser.parse("-", b"a = \n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            TomlParser.parse("-", b"= 5\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn toml_resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("app.toml", b"x = 1").unwrap().id(), "toml");
        // A `[section]` document beats JSON's bare-`[` sniff via STRONG.
        assert_eq!(
            reg.resolve("-", b"[server]\nhost = \"x\"\n").unwrap().id(),
            "toml"
        );
    }

    // ------------------------------------------------------------- INI -------

    const INI: &str = "\
; a comment
host = localhost
port = 8080

[database]
name = mydb
ssl = true
timeout = 30
";

    fn ini_parse(s: &str) -> Vec<Column> {
        IniParser.parse("-", s.as_bytes()).unwrap()
    }

    #[test]
    fn ini_flattens_sections_and_infers_types() {
        let cols = ini_parse(INI);
        assert_eq!(col(&cols, "host").cells[0], Value::Str("localhost".into()));
        assert_eq!(col(&cols, "port").cells[0], Value::Int(8080));
        assert_eq!(
            col(&cols, "database.name").cells[0],
            Value::Str("mydb".into())
        );
        assert_eq!(col(&cols, "database.ssl").cells[0], Value::Bool(true));
        assert_eq!(col(&cols, "database.timeout").cells[0], Value::Int(30));
        assert_eq!(col(&cols, "host").cells.len(), 1, "one row per config");
    }

    #[test]
    fn ini_quotes_colons_and_empties() {
        let cols = ini_parse("a = \"123\"\nb : bare\nc =\n");
        assert_eq!(col(&cols, "a").cells[0], Value::Str("123".into())); // quoted → string
        assert_eq!(col(&cols, "b").cells[0], Value::Str("bare".into())); // colon separator
        assert_eq!(col(&cols, "c").cells[0], Value::Null); // empty value → null
    }

    #[test]
    fn ini_malformed_line_errors() {
        assert!(matches!(
            IniParser.parse("-", b"no separator here\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn ini_helper_classification() {
        assert!(ini_is_comment("; x"));
        assert!(ini_is_comment("# x"));
        assert!(!ini_is_comment("k = v"));
        assert!(ini_is_section("[db]"));
        assert!(!ini_is_section("[]")); // empty inner
        assert!(!ini_is_section("[unclosed"));
        assert!(!ini_is_section("k = v"));
        assert_eq!(ini_kv_split("k = v"), Some(("k", " v")));
        assert_eq!(ini_kv_split("k : v"), Some(("k", " v")));
        assert_eq!(ini_kv_split("= v"), None); // empty key
        assert_eq!(ini_kv_split("no sep"), None);
        assert_eq!(parse_ini_value("'q'"), Value::Str("q".into()));
        assert_eq!(parse_ini_value("42"), Value::Int(42));
        // An unbalanced quote is NOT a quoted string — both ends must match, so
        // it stays a literal (and is type-inferred).
        assert_eq!(parse_ini_value("\"abc"), Value::Str("\"abc".into()));
        assert_eq!(parse_ini_value("'abc"), Value::Str("'abc".into()));
    }

    #[test]
    fn ini_sniff() {
        assert_eq!(IniParser.sniff(INI.as_bytes()), Some(STRONG)); // section + kv
        assert_eq!(
            IniParser.sniff(b"host = localhost\nport = 8080\n"),
            Some(TEXT)
        ); // kv, no section
           // A leading comment is skipped: the first *meaningful* line decides.
        assert_eq!(IniParser.sniff(b"; c\nhost = localhost\n"), Some(TEXT));
        assert_eq!(IniParser.sniff(b"[only_section]\n"), Some(TEXT)); // section, no kv
        assert_eq!(IniParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
        assert_eq!(IniParser.sniff(b"hello world\n"), None); // prose
        assert_eq!(IniParser.sniff(b"; only a comment\n"), None); // no meaningful line
    }

    #[test]
    fn ini_resolves_by_extension() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("app.ini", b"x = y").unwrap().id(), "ini");
        assert_eq!(reg.resolve("app.cfg", b"x = y").unwrap().id(), "ini");
        assert_eq!(reg.resolve("app.conf", b"x = y").unwrap().id(), "ini");
        // A sectioned bare-value config (invalid TOML) routes to INI by content.
        assert_eq!(
            reg.resolve("-", b"[db]\nhost = localhost\n").unwrap().id(),
            "ini"
        );
    }

    #[test]
    fn parsers_claim_their_extensions() {
        assert_eq!(TomlParser.extensions(), &["toml"]);
        assert_eq!(IniParser.extensions(), &["ini", "cfg", "conf"]);
    }
}
