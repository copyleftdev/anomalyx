//! Linux auditd parser — `/var/log/audit/audit.log` syscall/exec records.
//!
//! Each line is `type=<TYPE> msg=audit(<epoch>:<serial>): key=value ...` (an
//! optional `node=<host>` may precede `type=`). We pull the distinctive audit
//! message ID out of `msg=audit(...)` — `epoch` as a float (for `coll.cusum` /
//! cadence on bursty activity) and `serial` as the event id — then parse the
//! remaining `key=value` fields. `type` and `syscall` are the categorical
//! columns `dist` reads as exec/syscall mix drift.
//!
//! Field values are bare (type-inferred, e.g. `syscall=2` → `Int`),
//! double-quoted (`comm="cat"`), or single-quoted (auditd `USER_*` records carry
//! a `msg='...'` payload with spaces) — quoted values are kept verbatim as `Str`.
//!
//! Detected by the unmistakable `msg=audit(` signature; claims no extension
//! (`audit.log` is too generic to hijack).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct AuditdParser;

const AUDIT_MARKER: &str = "msg=audit(";

/// Splits the trailing `key=value` fields. Values are bare (until a space),
/// double-quoted, or single-quoted (which may contain spaces); a bare value is
/// type-inferred, a quoted value is kept verbatim as a string.
fn parse_fields(text: &str) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ' ' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            continue; // a token with no '=' is not a field
        }
        chars.next(); // consume '='
        let value = match chars.peek() {
            Some(&q @ ('"' | '\'')) => {
                chars.next();
                let mut s = String::new();
                for c in chars.by_ref() {
                    if c == q {
                        break;
                    }
                    s.push(c);
                }
                Value::Str(s)
            }
            _ => {
                let mut bare = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ' ' {
                        break;
                    }
                    bare.push(c);
                    chars.next();
                }
                infer::infer_scalar(&bare)
            }
        };
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// Parses one auditd record into `(epoch, serial, remaining-fields-text)`. The
/// remaining text is the line with the `msg=audit(...):` chunk removed (so it
/// holds `type=...` and the trailing fields). `None` if the line is not auditd.
fn parse_record(line: &str) -> Option<(f64, i64, String)> {
    // Split around the `msg=audit(EPOCH:SERIAL):` chunk without index math:
    // `prefix` holds `type=...` (and any `node=...`), `tail` the trailing fields.
    let (prefix, after_marker) = line.split_once(AUDIT_MARKER)?;
    let (id, tail) = after_marker.split_once(')')?;
    let (ts, serial) = id.split_once(':')?;
    let epoch = ts.parse::<f64>().ok().filter(|f| f.is_finite())?;
    let serial = serial.parse::<i64>().ok()?;
    let fields = tail.strip_prefix(':').unwrap_or(tail);
    Some((epoch, serial, format!("{prefix}{fields}")))
}

impl AuditdParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for AuditdParser {
    fn id(&self) -> &'static str {
        "auditd"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        line.contains(AUDIT_MARKER).then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let (epoch, serial, fields) = parse_record(line)
                .ok_or_else(|| self.err("not an auditd record: no valid msg=audit(...)"))?;
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            row.insert("epoch".into(), Value::Float(epoch));
            row.insert("serial".into(), Value::Int(serial));
            for (key, value) in parse_fields(&fields) {
                row.insert(key, value);
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

    const AUDIT: &str = concat!(
        r#"type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 pid=3538 uid=500 comm="cat" exe="/bin/cat""#,
        "\n",
        r#"type=CWD msg=audit(1364481363.243:24287): cwd="/home/user""#,
        "\n",
        r#"type=EXECVE msg=audit(1364481363.300:24288): argc=2 a0="ls" a1="-l""#,
        "\n",
    );

    fn parse(s: &str) -> Vec<Column> {
        AuditdParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn audit_id_becomes_epoch_and_serial() {
        let cols = parse(AUDIT);
        let epoch = col(&cols, "epoch");
        assert_eq!(epoch.ty, ColType::Float);
        assert_eq!(epoch.cells[0], Value::Float(1_364_481_363.243));
        assert_eq!(epoch.cells[2], Value::Float(1_364_481_363.300));
        let serial = col(&cols, "serial");
        assert_eq!(serial.ty, ColType::Int);
        assert_eq!(
            serial.cells,
            vec![Value::Int(24287), Value::Int(24287), Value::Int(24288)]
        );
    }

    #[test]
    fn type_and_syscall_are_columns() {
        let cols = parse(AUDIT);
        assert_eq!(
            col(&cols, "type").cells,
            vec![
                Value::Str("SYSCALL".into()),
                Value::Str("CWD".into()),
                Value::Str("EXECVE".into())
            ]
        );
        let syscall = col(&cols, "syscall");
        assert_eq!(syscall.cells[0], Value::Int(2)); // bare numeric → int
        assert_eq!(syscall.cells[1], Value::Null); // CWD record has no syscall
    }

    #[test]
    fn bare_and_quoted_values() {
        let cols = parse(AUDIT);
        assert_eq!(col(&cols, "success").cells[0], Value::Str("no".into()));
        assert_eq!(col(&cols, "exit").cells[0], Value::Int(-13)); // negative int
        assert_eq!(col(&cols, "comm").cells[0], Value::Str("cat".into())); // quoted
        assert_eq!(col(&cols, "exe").cells[0], Value::Str("/bin/cat".into()));
        assert_eq!(col(&cols, "cwd").cells[1], Value::Str("/home/user".into()));
        assert_eq!(col(&cols, "a0").cells[2], Value::Str("ls".into()));
    }

    #[test]
    fn single_quoted_value_with_spaces() {
        // auditd USER_* records carry a msg='...' payload containing spaces.
        let line = "type=USER_LOGIN msg=audit(1.5:9): pid=1 msg='op=login acct=root res=success'\n";
        let cols = AuditdParser.parse("-", line.as_bytes()).unwrap();
        assert_eq!(
            col(&cols, "msg").cells[0],
            Value::Str("op=login acct=root res=success".into())
        );
        assert_eq!(col(&cols, "pid").cells[0], Value::Int(1));
    }

    #[test]
    fn node_prefixed_records_parse() {
        // Remote logging prepends node=<host> before type=.
        let cols = AuditdParser
            .parse(
                "-",
                b"node=web01 type=SYSCALL msg=audit(1.0:1): syscall=59\n",
            )
            .unwrap();
        assert_eq!(col(&cols, "node").cells[0], Value::Str("web01".into()));
        assert_eq!(col(&cols, "type").cells[0], Value::Str("SYSCALL".into()));
        assert_eq!(col(&cols, "syscall").cells[0], Value::Int(59));
    }

    #[test]
    fn parse_fields_units() {
        assert_eq!(
            parse_fields(r#"a=1 b="two words" c='x y' d=-3"#),
            vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Str("two words".into())),
                ("c".into(), Value::Str("x y".into())),
                ("d".into(), Value::Int(-3)),
            ]
        );
    }

    #[test]
    fn malformed_records_error() {
        // No msg=audit( marker.
        assert!(matches!(
            AuditdParser.parse("-", b"this is not auditd\n"),
            Err(AxError::Parse { .. })
        ));
        // Marker present but the id has no ':' separator.
        assert!(matches!(
            AuditdParser.parse("-", b"type=X msg=audit(bad): a=1\n"),
            Err(AxError::Parse { .. })
        ));
        // Non-numeric serial.
        assert!(matches!(
            AuditdParser.parse("-", b"type=X msg=audit(1.0:zz): a=1\n"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_audit_marker() {
        assert_eq!(AuditdParser.sniff(AUDIT.as_bytes()), Some(STRONG));
        // type= without the audit marker is not auditd.
        assert_eq!(AuditdParser.sniff(b"type=SYSCALL foo=bar\n"), None);
        assert_eq!(AuditdParser.sniff(b"k=1 v=2\n"), None); // logfmt
        assert_eq!(AuditdParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
    }

    #[test]
    fn claims_no_extension() {
        assert!(AuditdParser.extensions().is_empty());
    }

    #[test]
    fn resolves_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("-", AUDIT.as_bytes()).unwrap().id(), "auditd");
        // A non-auditd `.log` is not hijacked.
        assert_eq!(reg.resolve("app.log", b"a,b\n1,2").unwrap().id(), "csv");
    }
}
