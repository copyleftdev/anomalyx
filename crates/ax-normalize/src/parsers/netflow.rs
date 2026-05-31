//! NetFlow / IPFIX parser — flow records via the nfdump CSV export.
//!
//! Raw NetFlow v9 / IPFIX is a stateful binary wire format (templates arrive in
//! separate packets), which fights both determinism and reliable file
//! detection. The canonical *analyzable* representation is `nfdump -o csv`, whose
//! header is an unmistakable signature. We parse that, renaming nfdump's cryptic
//! short names to canonical columns — `ibyt`→`bytes`, `ipkt`→`packets`,
//! `td`→`duration`, `sa`→`src_addr`, `dp`→`dst_port`, … — so the flow features
//! the detectors want are directly usable: `mv.mahalanobis` over
//! `(bytes, packets, duration)` catches exfil where each axis looks normal, and
//! `dst_port` feeds rare-port `dist` drift. The trailing `Summary` section is
//! not a flow record and is skipped.
//!
//! Detected by the nfdump header signature; claims no extension (nfdump CSV is
//! generically `*.csv`/`*.txt`).

use crate::infer;
use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct NetflowParser;

/// The first fields of an nfdump CSV header, in their canonical order — the
/// signature that distinguishes a flow export from any other CSV.
const SIGNATURE: &[&str] = &["ts", "te", "td", "sa", "da", "sp", "dp", "pr"];

/// Maps an nfdump short field name to a canonical column name; unknown fields
/// pass through under their original name.
fn canonical(field: &str) -> &str {
    match field {
        "ts" => "start",
        "te" => "end",
        "td" => "duration",
        "sa" => "src_addr",
        "da" => "dst_addr",
        "sp" => "src_port",
        "dp" => "dst_port",
        "pr" => "proto",
        "flg" => "flags",
        "ipkt" => "packets",
        "ibyt" => "bytes",
        "opkt" => "out_packets",
        "obyt" => "out_bytes",
        other => other,
    }
}

impl NetflowParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for NetflowParser {
    fn id(&self) -> &'static str {
        "netflow"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.lines().find(|l| !l.trim().is_empty())?;
        let fields: Vec<&str> = line.split(',').collect();
        fields.starts_with(SIGNATURE).then_some(STRONG)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());

        let header = lines.next().ok_or_else(|| self.err("empty nfdump CSV"))?;
        let fields: Vec<&str> = header.split(',').collect();
        if !fields.starts_with(SIGNATURE) {
            return Err(self.err("not nfdump CSV: unexpected header"));
        }
        let names: Vec<String> = fields.iter().map(|f| canonical(f).to_string()).collect();

        let mut builder = TableBuilder::new();
        for line in lines {
            // The CSV ends with a separate `Summary` stats section, not flows.
            if line.trim() == "Summary" {
                break;
            }
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for (name, value) in names.iter().zip(line.split(',')) {
                row.insert(name.clone(), infer::infer_scalar(value.trim()));
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

    const NFDUMP: &str = "\
ts,te,td,sa,da,sp,dp,pr,flg,ipkt,ibyt
2020-01-01 00:00:00.000,2020-01-01 00:00:01.000,1.000,10.0.0.1,8.8.8.8,12345,53,UDP,......,2,120
2020-01-01 00:00:02.000,2020-01-01 00:00:30.000,28.000,10.0.0.1,5.6.7.8,40000,443,TCP,.AP.SF,5000,9000000
Summary
flows,bytes,packets
2,9000120,5002
";

    fn parse(s: &str) -> Vec<Column> {
        NetflowParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn canonical_renames_the_flow_features() {
        let cols = parse(NFDUMP);
        // The mahalanobis triple, under canonical names (not ibyt/ipkt/td).
        let bytes = col(&cols, "bytes");
        assert_eq!(bytes.ty, ColType::Int);
        assert_eq!(bytes.cells, vec![Value::Int(120), Value::Int(9_000_000)]);
        assert_eq!(
            col(&cols, "packets").cells,
            vec![Value::Int(2), Value::Int(5000)]
        );
        let duration = col(&cols, "duration");
        assert_eq!(duration.ty, ColType::Float);
        assert_eq!(duration.cells, vec![Value::Float(1.0), Value::Float(28.0)]);
        // The cryptic nfdump names are gone.
        assert!(cols.iter().all(|c| c.name != "ibyt" && c.name != "td"));
    }

    #[test]
    fn addresses_ports_and_proto_are_typed() {
        let cols = parse(NFDUMP);
        assert_eq!(
            col(&cols, "src_addr").cells[0],
            Value::Str("10.0.0.1".into())
        );
        assert_eq!(
            col(&cols, "dst_addr").cells[1],
            Value::Str("5.6.7.8".into())
        );
        let dport = col(&cols, "dst_port");
        assert_eq!(dport.ty, ColType::Int);
        assert_eq!(dport.cells, vec![Value::Int(53), Value::Int(443)]);
        assert_eq!(col(&cols, "proto").cells[1], Value::Str("TCP".into()));
        assert_eq!(col(&cols, "flags").cells[1], Value::Str(".AP.SF".into()));
    }

    #[test]
    fn summary_section_is_not_parsed_as_flows() {
        // Two flow rows only; the Summary stats block is skipped.
        assert_eq!(col(&parse(NFDUMP), "bytes").cells.len(), 2);
    }

    #[test]
    fn canonical_units() {
        assert_eq!(canonical("ibyt"), "bytes");
        assert_eq!(canonical("ipkt"), "packets");
        assert_eq!(canonical("td"), "duration");
        assert_eq!(canonical("sa"), "src_addr");
        assert_eq!(canonical("dp"), "dst_port");
        assert_eq!(canonical("pr"), "proto");
        assert_eq!(canonical("unknown_field"), "unknown_field"); // pass-through
    }

    #[test]
    fn malformed_header_errors() {
        assert!(matches!(
            NetflowParser.parse("-", b"a,b,c\n1,2,3\n"),
            Err(AxError::Parse { .. })
        ));
        assert!(matches!(
            NetflowParser.parse("-", b""),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_the_nfdump_header() {
        assert_eq!(NetflowParser.sniff(NFDUMP.as_bytes()), Some(STRONG));
        // A header missing the full signature is not nfdump.
        assert_eq!(NetflowParser.sniff(b"ts,te,td,sa\n1,2,3,4"), None);
        assert_eq!(NetflowParser.sniff(b"a,b,c\n1,2,3"), None); // generic CSV
        assert_eq!(NetflowParser.sniff(b"{\"a\":1}"), None);
    }

    #[test]
    fn claims_no_extension() {
        assert!(NetflowParser.extensions().is_empty());
    }

    #[test]
    fn resolves_netflow_over_csv_by_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("-", NFDUMP.as_bytes()).unwrap().id(), "netflow");
        // A generic CSV stays CSV.
        assert_eq!(reg.resolve("-", b"a,b,c\n1,2,3").unwrap().id(), "csv");
    }
}
