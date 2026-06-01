//! Syslog parser — RFC 3164 (BSD) and RFC 5424 wire messages.
//!
//! Both variants begin with a `<PRI>` priority header (`PRI = facility*8 +
//! severity`, 0–191). We derive the numeric `facility`/`severity` ourselves from
//! that header (clean and deterministic) and delegate the harder dual-RFC field
//! parsing — BSD vs ISO timestamps, app/host/proc IDs, RFC 5424 structured data
//! — to `syslog_loose`. One row per message, with columns the detectors want:
//! `severity`/`facility` for event-rate `dist` drift, `hostname` for rare-host
//! `structural`/`dist`, and rows-as-an-ordered-series for off-hours `contextual`
//! (`--period 24`).
//!
//! Determinism: `syslog_loose`'s default entry point fills a year-less RFC 3164
//! timestamp from the wall clock and the local time zone. We instead pin a fixed
//! year and UTC, so the same bytes always normalize identically (the real
//! month/day/time are preserved; only the absent RFC 3164 year is a sentinel).
//!
//! Detected by the `<PRI>` header **or** the PRI-less file format that
//! rsyslog/syslog-ng actually write (ISO-8601 or BSD timestamp, then host and
//! tag) — recognized by `syslog_loose` extracting a timestamp + host + app.
//! `facility`/`severity` exist only when a `<PRI>` is present. Claims `.syslog`
//! (a plain `.log` is too generic). A line that is neither is a clean parse error.

use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use chrono::Utc;
use std::collections::BTreeMap;
use syslog_loose::{parse_message_with_year_tz, ProcId, Protocol, Variant};

#[derive(Debug, Default, Clone)]
pub struct SyslogParser;

/// The RFC 3164 year is unknowable from the wire; pin a sentinel so the parse is
/// deterministic (the month/day/time carry the real information).
const SENTINEL_YEAR: i32 = 1970;

/// Whether a line is syslog: either a `<PRI>` wire header, or the PRI-less file
/// format (what rsyslog/syslog-ng actually write to `/var/log/syslog`) — which
/// we recognize by `syslog_loose` extracting a timestamp **and** a hostname
/// **and** an appname. Requiring all three keeps a timestamp-leading CSV row
/// (no space-delimited host/app after the time) from being mistaken for syslog.
fn looks_like_syslog(line: &str) -> bool {
    if parse_pri(line).is_some() {
        return true;
    }
    let m = parse_message_with_year_tz(line, |_| SENTINEL_YEAR, Some(Utc), Variant::Either);
    m.timestamp.is_some() && m.hostname.is_some() && m.appname.is_some()
}

/// Parses the leading `<PRI>` header into `(facility, severity)`. `PRI = facility
/// * 8 + severity` and is 0–191; anything else is not a syslog priority.
fn parse_pri(line: &str) -> Option<(i64, i64)> {
    let rest = line.strip_prefix('<')?;
    let end = rest.find('>')?;
    let pri: u16 = rest[..end].parse().ok()?;
    (pri <= 191).then_some(((pri / 8) as i64, (pri % 8) as i64))
}

impl SyslogParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for SyslogParser {
    fn id(&self) -> &'static str {
        "syslog"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["syslog"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        looks_like_syslog(line).then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let pri = parse_pri(line);
            let msg =
                parse_message_with_year_tz(line, |_| SENTINEL_YEAR, Some(Utc), Variant::Either);
            // Accept a line with a `<PRI>` header (wire format) OR a recognizable
            // timestamp (the PRI-less file format rsyslog/syslog-ng write).
            // `syslog_loose` only yields a timestamp once it has also parsed the
            // host/tag that follow it, so the timestamp alone is a sufficient gate.
            if pri.is_none() && msg.timestamp.is_none() {
                return Err(
                    self.err("not a syslog line: no <PRI> header and no recognizable timestamp")
                );
            }

            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            // facility/severity come only from the `<PRI>` header; a file-format
            // line has none, so those columns are simply absent for it.
            if let Some((facility, severity)) = pri {
                row.insert("facility".into(), Value::Int(facility));
                row.insert("severity".into(), Value::Int(severity));
            }
            row.insert(
                "protocol".into(),
                Value::Str(
                    match msg.protocol {
                        Protocol::RFC3164 => "RFC3164",
                        Protocol::RFC5424(_) => "RFC5424",
                    }
                    .to_string(),
                ),
            );
            if let Some(ts) = msg.timestamp {
                row.insert("timestamp".into(), Value::Str(ts.to_string()));
            }
            if let Some(host) = msg.hostname {
                row.insert("hostname".into(), Value::Str(host.to_string()));
            }
            if let Some(app) = msg.appname {
                row.insert("appname".into(), Value::Str(app.to_string()));
            }
            if let Some(procid) = msg.procid {
                let v = match procid {
                    ProcId::PID(pid) => Value::Int(pid as i64),
                    ProcId::Name(name) => Value::Str(name.to_string()),
                };
                row.insert("procid".into(), v);
            }
            if let Some(msgid) = msg.msgid {
                row.insert("msgid".into(), Value::Str(msgid.to_string()));
            }
            for element in &msg.structured_data {
                for (key, value) in &element.params {
                    row.insert(
                        format!("sd.{}.{}", element.id, key),
                        Value::Str(value.to_string()),
                    );
                }
            }
            row.insert("message".into(), Value::Str(msg.msg.to_string()));
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const SYSLOG: &str = concat!(
        r#"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [exampleSDID@32473 iut="3" eventID="1011"] App event log entry"#,
        "\n",
        "<34>Oct 11 22:14:15 mymachine su[567]: 'su root' failed for lonvick\n",
    );

    fn parse(s: &str) -> Vec<Column> {
        SyslogParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn priority_decodes_to_facility_and_severity() {
        let cols = parse(SYSLOG);
        let fac = col(&cols, "facility");
        let sev = col(&cols, "severity");
        assert_eq!(fac.ty, ColType::Int);
        assert_eq!(sev.ty, ColType::Int);
        assert_eq!(fac.cells, vec![Value::Int(20), Value::Int(4)]); // 165/8, 34/8
        assert_eq!(sev.cells, vec![Value::Int(5), Value::Int(2)]); // 165%8, 34%8
    }

    #[test]
    fn both_rfc_variants_parse_their_fields() {
        let cols = parse(SYSLOG);
        assert_eq!(
            col(&cols, "protocol").cells,
            vec![Value::Str("RFC5424".into()), Value::Str("RFC3164".into())]
        );
        assert_eq!(
            col(&cols, "hostname").cells,
            vec![
                Value::Str("mymachine.example.com".into()),
                Value::Str("mymachine".into())
            ]
        );
        assert_eq!(
            col(&cols, "appname").cells,
            vec![Value::Str("evntslog".into()), Value::Str("su".into())]
        );
        assert_eq!(
            col(&cols, "procid").cells,
            vec![Value::Int(1234), Value::Int(567)]
        );
    }

    #[test]
    fn rfc5424_only_fields_pad_with_null() {
        let cols = parse(SYSLOG);
        // msgid and structured data exist only on the RFC 5424 row.
        assert_eq!(col(&cols, "msgid").cells[0], Value::Str("ID47".into()));
        assert_eq!(col(&cols, "msgid").cells[1], Value::Null);
        let sd = col(&cols, "sd.exampleSDID@32473.iut");
        assert_eq!(sd.cells[0], Value::Str("3".into()));
        assert_eq!(sd.cells[1], Value::Null);
        assert_eq!(
            col(&cols, "sd.exampleSDID@32473.eventID").cells[0],
            Value::Str("1011".into())
        );
    }

    #[test]
    fn message_body_is_captured() {
        let cols = parse(SYSLOG);
        let msg = col(&cols, "message");
        assert_eq!(msg.cells[0], Value::Str("App event log entry".into()));
        assert_eq!(
            msg.cells[1],
            Value::Str("'su root' failed for lonvick".into())
        );
    }

    #[test]
    fn deterministic_across_calls() {
        // Same bytes → byte-identical columns, despite RFC 3164's missing year
        // (pinned to a sentinel, never the wall clock).
        assert_eq!(
            format!("{:?}", parse(SYSLOG)),
            format!("{:?}", parse(SYSLOG))
        );
        // The RFC 3164 timestamp uses the sentinel year, deterministically.
        let cols = parse(SYSLOG);
        let ts = col(&cols, "timestamp");
        match &ts.cells[1] {
            Value::Str(s) => assert!(s.starts_with("1970-"), "sentinel year, got {s}"),
            other => panic!("expected Str timestamp, got {other:?}"),
        }
    }

    #[test]
    fn parse_pri_units() {
        assert_eq!(parse_pri("<0>x"), Some((0, 0)));
        assert_eq!(parse_pri("<34>x"), Some((4, 2)));
        assert_eq!(parse_pri("<165>x"), Some((20, 5)));
        assert_eq!(parse_pri("<191>x"), Some((23, 7))); // max valid
        assert_eq!(parse_pri("<192>x"), None); // out of range
        assert_eq!(parse_pri("<abc>x"), None); // not a number
        assert_eq!(parse_pri("<34"), None); // unterminated
        assert_eq!(parse_pri("no bracket"), None);
    }

    #[test]
    fn malformed_lines_error() {
        assert!(matches!(
            SyslogParser.parse("-", b"this is not syslog\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            SyslogParser.parse("-", b"<192>priority out of range\n"),
            Err(AxError::Parse { .. })
        ));
    }

    /// The PRI-less file formats that rsyslog/syslog-ng actually write to disk.
    const ISO_FILE: &[u8] =
        b"2026-06-01T09:14:57.403686-07:00 4ubox NetworkManager[3524]: dhcp4 beginning\n";
    const BSD_FILE: &[u8] = b"Jun  1 09:14:57 4ubox NetworkManager[3524]: dhcp4 beginning\n";

    #[test]
    fn sniff_keys_on_pri_header() {
        assert_eq!(SyslogParser.sniff(SYSLOG.as_bytes()), Some(STRONG));
        assert_eq!(
            SyslogParser.sniff(b"<13>Feb  5 17:32:18 host app: msg\n"),
            Some(STRONG)
        );
        assert_eq!(SyslogParser.sniff(b"<999>bad pri\n"), None); // > 191
        assert_eq!(SyslogParser.sniff(b"<?xml version=\"1.0\"?>"), None); // XML, not PRI
        assert_eq!(SyslogParser.sniff(b"plain text line\n"), None);
        assert_eq!(SyslogParser.sniff(b"{\"a\":1}"), None);
        assert_eq!(SyslogParser.sniff(b"a,b,c\n1,2,3"), None);
    }

    #[test]
    fn sniff_recognizes_pri_less_file_format() {
        // The real /var/log/syslog format (no <PRI>): ISO-8601 and BSD timestamps.
        assert_eq!(SyslogParser.sniff(ISO_FILE), Some(STRONG));
        assert_eq!(SyslogParser.sniff(BSD_FILE), Some(STRONG));
        // But a timestamp-leading CSV (no space-delimited host/app) is NOT syslog.
        assert_eq!(SyslogParser.sniff(b"2026-06-01T09:14:57,42,foo\n"), None);
        // And it wins over the greedy `ini` sniff through the registry.
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("-", ISO_FILE).unwrap().id(), "syslog");
    }

    #[test]
    fn pri_less_file_line_parses_without_facility_severity() {
        let cols = SyslogParser.parse("-", ISO_FILE).unwrap();
        // The fields syslog_loose recovers are present...
        assert_eq!(col(&cols, "hostname").cells[0], Value::Str("4ubox".into()));
        assert_eq!(
            col(&cols, "appname").cells[0],
            Value::Str("NetworkManager".into())
        );
        assert_eq!(col(&cols, "procid").cells[0], Value::Int(3524));
        assert!(
            matches!(&col(&cols, "timestamp").cells[0], Value::Str(s) if s.starts_with("2026-06-01"))
        );
        // ...but facility/severity columns don't exist (no <PRI> to derive them).
        assert!(cols
            .iter()
            .all(|c| c.name != "facility" && c.name != "severity"));
    }

    #[test]
    fn claims_syslog_extension() {
        assert_eq!(SyslogParser.extensions(), &["syslog"]);
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(
            reg.resolve("app.syslog", b"<34>Oct 11 22:14:15 h a: m")
                .unwrap()
                .id(),
            "syslog"
        );
        assert_eq!(reg.resolve("-", SYSLOG.as_bytes()).unwrap().id(), "syslog");
    }
}
