//! DNS query log parser — dnsmasq / Pi-hole style query lines.
//!
//! DNS is a favorite covert channel, so beyond extracting the query we compute
//! the features that expose tunnelling: `qname_length` and `qname_entropy`
//! (Shannon entropy of the query name) feed `point` detection of DGA / exfil
//! names (long, high-entropy), and `timestamp_epoch` feeds `cadence` on query
//! timing (beaconing). `qtype` (e.g. `TXT`) and `client` round out the row.
//!
//! Parses the dnsmasq query line shape `<time> dnsmasq[pid]: query[TYPE] NAME
//! from CLIENT`; non-query lines (forwarded/reply/cached) produce no rows. The
//! BSD timestamp has no year, so it is parsed with a fixed sentinel year (UTC) —
//! deterministic, never the wall clock. Detected by a parseable query line;
//! claims no extension (DNS logs are generically `*.log`).

use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct DnsParser;

/// The RFC 3164 timestamp carries no year; pin a sentinel so the epoch is
/// deterministic (the month/day/time carry the real information).
const SENTINEL_YEAR: i32 = 1970;

/// One parsed dnsmasq query line.
struct DnsQuery<'a> {
    timestamp: Option<&'a str>,
    qtype: &'a str,
    qname: &'a str,
    client: &'a str,
}

/// Shannon entropy (bits) of a string's character distribution. High for the
/// random-looking labels of DGA domains and base32/64 exfil payloads.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Parses the dnsmasq BSD timestamp (`Mmm dd HH:MM:SS`, no year) to Unix seconds
/// using the sentinel year and UTC. `None` if it doesn't parse.
fn parse_epoch(timestamp: &str) -> Option<i64> {
    let stamped = format!("{SENTINEL_YEAR} {timestamp}");
    chrono::NaiveDateTime::parse_from_str(&stamped, "%Y %b %e %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc().timestamp())
}

/// Parses a `... query[TYPE] NAME from CLIENT` line. `None` for non-query lines
/// (the type must begin with an uppercase letter, ruling out prose like
/// `query[0] x from y`).
fn parse_query(line: &str) -> Option<DnsQuery<'_>> {
    let after = line.split_once("query[")?.1;
    let (qtype, rest) = after.split_once(']')?;
    if !qtype.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let (qname, client) = rest.trim_start().split_once(" from ")?;
    let qname = qname.trim();
    let client = client.trim();
    if qname.is_empty() {
        return None;
    }
    // The BSD timestamp is the leading 15 ASCII chars, when present.
    let timestamp = line.get(..15);
    Some(DnsQuery {
        timestamp,
        qtype,
        qname,
        client,
    })
}

impl DnsParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for DnsParser {
    fn id(&self) -> &'static str {
        "dns"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        text.lines()
            .take(64)
            .any(|l| parse_query(l).is_some())
            .then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        let mut queries = 0usize;
        for line in text.lines() {
            let Some(q) = parse_query(line) else {
                continue; // forwarded/reply/cached/config lines are not queries
            };
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            if let Some(ts) = q.timestamp {
                row.insert("timestamp".into(), Value::Str(ts.to_string()));
                if let Some(epoch) = parse_epoch(ts) {
                    row.insert("timestamp_epoch".into(), Value::Int(epoch));
                }
            }
            row.insert("qtype".into(), Value::Str(q.qtype.to_string()));
            row.insert("qname".into(), Value::Str(q.qname.to_string()));
            row.insert(
                "qname_length".into(),
                Value::Int(q.qname.chars().count() as i64),
            );
            row.insert(
                "qname_entropy".into(),
                Value::Float(shannon_entropy(q.qname)),
            );
            row.insert("client".into(), Value::Str(q.client.to_string()));
            builder.push_row(row);
            queries += 1;
        }
        if queries == 0 {
            return Err(self.err("no DNS query lines found"));
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const DNS: &str = "\
Jan  1 00:00:00 dnsmasq[1234]: query[A] example.com from 10.0.0.1
Jan  1 00:00:00 dnsmasq[1234]: forwarded example.com to 8.8.8.8
Jan  1 00:00:01 dnsmasq[1234]: reply example.com is 1.2.3.4
Jan  1 00:00:05 dnsmasq[1234]: query[TXT] aGVsbG8gZXhmaWwK.evil.example from 10.0.0.2
";

    fn parse(s: &str) -> Vec<Column> {
        DnsParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn only_query_lines_become_rows() {
        let cols = parse(DNS);
        // forwarded + reply lines are skipped → 2 query rows.
        assert_eq!(col(&cols, "qname").cells.len(), 2);
        assert_eq!(
            col(&cols, "qname").cells,
            vec![
                Value::Str("example.com".into()),
                Value::Str("aGVsbG8gZXhmaWwK.evil.example".into())
            ]
        );
        assert_eq!(
            col(&cols, "qtype").cells,
            vec![Value::Str("A".into()), Value::Str("TXT".into())]
        );
        assert_eq!(col(&cols, "client").cells[1], Value::Str("10.0.0.2".into()));
    }

    #[test]
    fn computed_features_for_dga_exfil_detection() {
        let cols = parse(DNS);
        let len = col(&cols, "qname_length");
        assert_eq!(len.ty, ColType::Int);
        assert_eq!(len.cells[0], Value::Int(11)); // "example.com"
        let entropy = col(&cols, "qname_entropy");
        assert_eq!(entropy.ty, ColType::Float);
        // The exfil-style name has higher entropy than the plain domain.
        let (Value::Float(plain), Value::Float(exfil)) = (&entropy.cells[0], &entropy.cells[1])
        else {
            panic!("expected float entropies")
        };
        assert!(exfil > plain, "{exfil} should exceed {plain}");
    }

    #[test]
    fn timestamp_parsed_to_epoch_with_sentinel_year() {
        let cols = parse(DNS);
        let epoch = col(&cols, "timestamp_epoch");
        assert_eq!(epoch.ty, ColType::Int);
        // 1970-01-01 00:00:00 UTC = 0; the second query is 5s later.
        assert_eq!(epoch.cells, vec![Value::Int(0), Value::Int(5)]);
        assert_eq!(
            col(&cols, "timestamp").cells[0],
            Value::Str("Jan  1 00:00:00".into())
        );
    }

    #[test]
    fn shannon_entropy_units() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaa"), 0.0); // one symbol → no entropy
        assert_eq!(shannon_entropy("ab"), 1.0); // two equal symbols → 1 bit
        assert_eq!(shannon_entropy("aabb"), 1.0);
        assert_eq!(shannon_entropy("abcd"), 2.0); // four equal symbols → 2 bits
    }

    #[test]
    fn parse_epoch_units() {
        assert_eq!(parse_epoch("Jan  1 00:00:00"), Some(0));
        assert_eq!(parse_epoch("Jan  1 00:00:05"), Some(5));
        assert_eq!(parse_epoch("not a timestamp"), None);
    }

    #[test]
    fn parse_query_units() {
        let q = parse_query("Jan  1 00:00:00 dnsmasq[1]: query[A] a.com from 1.2.3.4").unwrap();
        assert_eq!(q.qtype, "A");
        assert_eq!(q.qname, "a.com");
        assert_eq!(q.client, "1.2.3.4");
        // Non-query lines and prose are rejected.
        assert!(parse_query("Jan  1 00:00:00 dnsmasq[1]: forwarded a.com to 8.8.8.8").is_none());
        assert!(parse_query("the query[0] index from array").is_none()); // type not uppercase
        assert!(parse_query("query[A]  from 1.2.3.4").is_none()); // empty name
    }

    #[test]
    fn no_query_lines_is_an_error() {
        assert!(matches!(
            DnsParser.parse("-", b"just some text\nno queries here\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            DnsParser.parse("-", b""),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_a_query_line() {
        assert_eq!(DnsParser.sniff(DNS.as_bytes()), Some(STRONG));
        // A log that starts with non-query lines still sniffs (scans ahead).
        assert_eq!(
            DnsParser.sniff(b"Jan  1 00:00:00 dnsmasq[1]: started\nJan  1 00:00:01 dnsmasq[1]: query[A] x.com from 1.1.1.1\n"),
            Some(STRONG)
        );
        assert_eq!(DnsParser.sniff(b"a,b,c\n1,2,3"), None);
        assert_eq!(DnsParser.sniff(b"hello world\n"), None);
    }

    #[test]
    fn claims_no_extension() {
        assert!(DnsParser.extensions().is_empty());
    }

    #[test]
    fn resolves_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("-", DNS.as_bytes()).unwrap().id(), "dns");
    }
}
