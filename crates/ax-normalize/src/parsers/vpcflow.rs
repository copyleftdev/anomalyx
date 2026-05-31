//! AWS VPC Flow Logs parser — cloud-native network telemetry (space-delimited).
//!
//! A VPC flow log file is whitespace-delimited with a header line naming the
//! fields (the default v2 layout, or a custom field order). We use the header to
//! map columns, renaming AWS's names to the same canonical schema as the NetFlow
//! parser — `srcaddr`→`src_addr`, `dstport`→`dst_port`, `protocol`→`proto`, … —
//! and synthesize `duration` = `end - start`. So the same flow anomalies apply
//! with zero new infra: `mv.mahalanobis` over `(bytes, packets, duration)` and
//! rare-port `dist` on `dst_port`. The AWS `-` placeholder (e.g. a `NODATA`
//! record) becomes `Null` (honest absence).
//!
//! Detected by the VPC header signature (`srcaddr` + `dstaddr` + `dstport`);
//! claims no extension (flow log files are generically `*.log`).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct VpcFlowParser;

/// Header field names that together identify a VPC flow log (regardless of the
/// custom field order AWS allows).
const SIGNATURE: &[&str] = &["srcaddr", "dstaddr", "dstport"];

fn is_vpc_header(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    SIGNATURE.iter().all(|field| tokens.contains(field))
}

/// Maps a VPC flow log field name to the canonical NetFlow-style column name;
/// other fields pass through unchanged.
fn canonical(field: &str) -> &str {
    match field {
        "srcaddr" => "src_addr",
        "dstaddr" => "dst_addr",
        "srcport" => "src_port",
        "dstport" => "dst_port",
        "protocol" => "proto",
        "interface-id" => "interface_id",
        "account-id" => "account_id",
        "log-status" => "log_status",
        other => other,
    }
}

impl VpcFlowParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for VpcFlowParser {
    fn id(&self) -> &'static str {
        "vpcflow"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        is_vpc_header(line).then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());

        let header = lines.next().ok_or_else(|| self.err("empty VPC flow log"))?;
        if !is_vpc_header(header) {
            return Err(self.err("not a VPC flow log: header is missing srcaddr/dstaddr/dstport"));
        }
        let names: Vec<String> = header
            .split_whitespace()
            .map(|f| canonical(f).to_string())
            .collect();

        let mut builder = TableBuilder::new();
        for line in lines {
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for (name, value) in names.iter().zip(line.split_whitespace()) {
                // AWS uses `-` for a field with no value (e.g. a NODATA record).
                let cell = if value == "-" {
                    Value::Null
                } else {
                    infer::infer_scalar(value)
                };
                row.insert(name.clone(), cell);
            }
            // Synthesize flow duration from the epoch start/end when both present.
            if let (Some(Value::Int(start)), Some(Value::Int(end))) =
                (row.get("start"), row.get("end"))
            {
                if let Some(d) = end.checked_sub(*start) {
                    row.insert("duration".to_string(), Value::Int(d));
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

    const VPC: &str = "\
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789010 eni-abc 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK
2 123456789010 eni-abc 172.31.9.69 172.31.9.12 0 0 - - - 1431280876 1431280934 - NODATA
";

    fn parse(s: &str) -> Vec<Column> {
        VpcFlowParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn canonical_flow_columns_are_typed() {
        let cols = parse(VPC);
        assert_eq!(
            col(&cols, "src_addr").cells[0],
            Value::Str("172.31.16.139".into())
        );
        let dport = col(&cols, "dst_port");
        assert_eq!(dport.ty, ColType::Int);
        assert_eq!(dport.cells, vec![Value::Int(22), Value::Int(0)]);
        assert_eq!(col(&cols, "proto").cells[0], Value::Int(6)); // protocol → proto
        assert_eq!(col(&cols, "bytes").cells[0], Value::Int(4249));
        // The AWS short names are gone.
        assert!(cols
            .iter()
            .all(|c| c.name != "srcaddr" && c.name != "dstport"));
    }

    #[test]
    fn duration_is_synthesized_from_start_end() {
        let cols = parse(VPC);
        let dur = col(&cols, "duration");
        assert_eq!(dur.ty, ColType::Int);
        assert_eq!(dur.cells, vec![Value::Int(60), Value::Int(58)]);
    }

    #[test]
    fn dash_placeholder_is_null() {
        let cols = parse(VPC);
        // The second record is NODATA: packets/bytes/action are `-`.
        assert_eq!(col(&cols, "packets").cells[1], Value::Null);
        assert_eq!(col(&cols, "bytes").cells[1], Value::Null);
        assert_eq!(col(&cols, "action").cells[1], Value::Null);
        assert_eq!(col(&cols, "action").cells[0], Value::Str("ACCEPT".into()));
        assert_eq!(
            col(&cols, "log_status").cells[1],
            Value::Str("NODATA".into())
        );
    }

    #[test]
    fn canonical_units() {
        assert_eq!(canonical("srcaddr"), "src_addr");
        assert_eq!(canonical("dstport"), "dst_port");
        assert_eq!(canonical("protocol"), "proto");
        assert_eq!(canonical("log-status"), "log_status");
        assert_eq!(canonical("packets"), "packets"); // pass-through
        assert_eq!(canonical("tcp-flags"), "tcp-flags"); // custom field pass-through
    }

    #[test]
    fn malformed_header_errors() {
        assert!(matches!(
            VpcFlowParser.parse("-", b"a b c\n1 2 3\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            VpcFlowParser.parse("-", b""),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_the_vpc_header() {
        assert_eq!(VpcFlowParser.sniff(VPC.as_bytes()), Some(STRONG));
        // A header missing one signature field is not VPC.
        assert_eq!(VpcFlowParser.sniff(b"srcaddr dstaddr action\n1 2 3"), None);
        assert_eq!(VpcFlowParser.sniff(b"a b c\n1 2 3"), None);
        assert_eq!(VpcFlowParser.sniff(b"ts,te,td,sa\n"), None); // nfdump (comma)
    }

    #[test]
    fn claims_no_extension() {
        assert!(VpcFlowParser.extensions().is_empty());
    }

    #[test]
    fn resolves_vpcflow_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("-", VPC.as_bytes()).unwrap().id(), "vpcflow");
    }
}
