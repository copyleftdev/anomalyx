//! PCAP / PCAPNG packet-capture parser — the ground truth of network analysis.
//!
//! A capture is decoded to **one row per packet** with the columns the detectors
//! need: `timestamp` (epoch seconds, `Float`) — the marquee input for
//! **beaconing/C2 detection via `cadence`** on inter-arrival times — plus
//! `length` (original) and `caplen` for volume `point` spikes, and, when the
//! link layer is Ethernet or raw IP, `src_ip` / `dst_ip` / `ip_proto` for `mv`
//! over per-packet features.
//!
//! The container (both legacy PCAP and PCAPNG, either byte order, µs or ns
//! resolution) is decoded by `pcap-parser`; the L2/L3 headers by `etherparse`.
//! Binary magic (confidence `MAGIC`); extensions `.pcap` / `.pcapng` / `.cap`.
//! Behind the default-on `pcap` feature.

use crate::parser::{Confidence, FormatParser, MAGIC};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use pcap_parser::pcapng::Block;
use pcap_parser::{create_reader, Linktype, PcapBlockOwned, PcapError};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct PcapParser;

/// The legacy-pcap magics (µs/ns × LE/BE) and the PCAPNG section-header magic.
const MAGICS: [[u8; 4]; 5] = [
    [0xd4, 0xc3, 0xb2, 0xa1], // legacy µs, little-endian
    [0xa1, 0xb2, 0xc3, 0xd4], // legacy µs, big-endian
    [0x4d, 0x3c, 0xb2, 0xa1], // legacy ns, little-endian
    [0xa1, 0xb2, 0x3c, 0x4d], // legacy ns, big-endian
    [0x0a, 0x0d, 0x0d, 0x0a], // PCAPNG section header block
];

/// The default PCAPNG timestamp resolution (microseconds) when an interface
/// declares none.
const DEFAULT_TS_RESOLUTION: u64 = 1_000_000;

/// Builds the per-packet row shared by every block type. `timestamp` is omitted
/// (left `Null`) when a block carries none (e.g. a PCAPNG simple packet).
fn packet_row(timestamp: Option<f64>, orig_len: u32, cap_len: u32) -> BTreeMap<String, Value> {
    let mut row = BTreeMap::new();
    if let Some(ts) = timestamp.filter(|t| t.is_finite()) {
        row.insert("timestamp".to_string(), Value::Float(ts));
    }
    row.insert("length".to_string(), Value::Int(i64::from(orig_len)));
    row.insert("caplen".to_string(), Value::Int(i64::from(cap_len)));
    row
}

/// Decodes the L3 addresses from a packet, given its link type. Best-effort: an
/// unsupported link type or an undecodable packet simply contributes no L3
/// columns (the packet still has its timestamp/length).
fn add_l3(linktype: Linktype, data: &[u8], row: &mut BTreeMap<String, Value>) {
    use etherparse::{NetSlice, SlicedPacket};
    let sliced = match linktype.0 {
        1 => SlicedPacket::from_ethernet(data),         // ETHERNET
        101 | 228 | 229 => SlicedPacket::from_ip(data), // RAW / IPV4 / IPV6
        _ => return,
    };
    let Ok(sliced) = sliced else { return };
    match sliced.net {
        Some(NetSlice::Ipv4(ip)) => {
            let h = ip.header();
            row.insert("src_ip".into(), Value::Str(h.source_addr().to_string()));
            row.insert(
                "dst_ip".into(),
                Value::Str(h.destination_addr().to_string()),
            );
            row.insert("ip_proto".into(), Value::Int(i64::from(h.protocol().0)));
        }
        Some(NetSlice::Ipv6(ip)) => {
            let h = ip.header();
            row.insert("src_ip".into(), Value::Str(h.source_addr().to_string()));
            row.insert(
                "dst_ip".into(),
                Value::Str(h.destination_addr().to_string()),
            );
            row.insert("ip_proto".into(), Value::Int(i64::from(h.next_header().0)));
        }
        _ => {}
    }
}

impl PcapParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for PcapParser {
    fn id(&self) -> &'static str {
        "pcap"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pcap", "pcapng", "cap"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let head = bytes.get(..4)?;
        MAGICS.iter().any(|m| m == head).then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let mut reader = create_reader(65536, bytes).map_err(|e| self.err(format!("{e:?}")))?;
        let mut builder = TableBuilder::new();
        let mut linktype = Linktype::ETHERNET; // legacy header / NG interface sets this
        let mut nanosecond = false; // legacy timestamp precision
        let mut resolution = DEFAULT_TS_RESOLUTION; // NG timestamp resolution

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            linktype = hdr.network;
                            nanosecond = hdr.is_nanosecond_precision();
                        }
                        PcapBlockOwned::Legacy(b) => {
                            let scale = if nanosecond { 1e-9 } else { 1e-6 };
                            let ts = f64::from(b.ts_sec) + f64::from(b.ts_usec) * scale;
                            let mut row = packet_row(Some(ts), b.origlen, b.caplen);
                            add_l3(linktype, b.data, &mut row);
                            builder.push_row(row);
                        }
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            linktype = idb.linktype;
                            resolution = idb.ts_resolution().unwrap_or(DEFAULT_TS_RESOLUTION);
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                            let ts = epb.decode_ts_f64(0, resolution);
                            let mut row = packet_row(Some(ts), epb.origlen, epb.caplen);
                            add_l3(linktype, epb.data, &mut row);
                            builder.push_row(row);
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                            let caplen = spb.data.len() as u32;
                            let mut row = packet_row(None, spb.origlen, caplen);
                            add_l3(linktype, spb.data, &mut row);
                            builder.push_row(row);
                        }
                        PcapBlockOwned::NG(_) => {} // section header, stats, name resolution …
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    // Grow the buffer; if no more data can be read, stop.
                    if reader.refill().is_err() {
                        break;
                    }
                }
                Err(e) => return Err(self.err(format!("{e:?}"))),
            }
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    // ---- byte builders for fixtures --------------------------------------

    fn push_u16(b: &mut Vec<u8>, v: u16) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u32(b: &mut Vec<u8>, v: u32) {
        b.extend_from_slice(&v.to_le_bytes());
    }

    /// A legacy little-endian PCAP with two packets (4 bytes of data each); the
    /// second has `orig_len > caplen` (a truncated capture).
    fn build_legacy_pcap(nanosecond: bool) -> Vec<u8> {
        let mut b = Vec::new();
        let magic: u32 = if nanosecond { 0xa1b2_3c4d } else { 0xa1b2_c3d4 };
        push_u32(&mut b, magic);
        push_u16(&mut b, 2); // version major
        push_u16(&mut b, 4); // version minor
        push_u32(&mut b, 0); // thiszone
        push_u32(&mut b, 0); // sigfigs
        push_u32(&mut b, 65535); // snaplen
        push_u32(&mut b, 1); // network = Ethernet

        // packet 0: ts 1000.0, caplen 4, origlen 4
        push_u32(&mut b, 1000);
        push_u32(&mut b, 0);
        push_u32(&mut b, 4);
        push_u32(&mut b, 4);
        b.extend_from_slice(&[0, 0, 0, 0]);

        // packet 1: ts 1001 + frac, caplen 4, origlen 60 (truncated)
        let frac: u32 = if nanosecond { 500_000_000 } else { 500_000 };
        push_u32(&mut b, 1001);
        push_u32(&mut b, frac);
        push_u32(&mut b, 4);
        push_u32(&mut b, 60);
        b.extend_from_slice(&[0, 0, 0, 0]);
        b
    }

    /// A minimal PCAPNG (SHB + IDB + one Enhanced Packet) at ts 1.5s.
    fn build_pcapng() -> Vec<u8> {
        let mut b = Vec::new();
        // Section Header Block (28 bytes).
        push_u32(&mut b, 0x0a0d_0d0a);
        push_u32(&mut b, 28);
        push_u32(&mut b, 0x1a2b_3c4d); // byte-order magic
        push_u16(&mut b, 1); // major
        push_u16(&mut b, 0); // minor
        push_u32(&mut b, 0xffff_ffff); // section length = -1 (low)
        push_u32(&mut b, 0xffff_ffff); // section length = -1 (high)
        push_u32(&mut b, 28);
        // Interface Description Block (20 bytes): linktype Ethernet, no options.
        push_u32(&mut b, 0x0000_0001);
        push_u32(&mut b, 20);
        push_u16(&mut b, 1); // linktype Ethernet
        push_u16(&mut b, 0); // reserved
        push_u32(&mut b, 65535); // snaplen
        push_u32(&mut b, 20);
        // Enhanced Packet Block (36 bytes): ts_low = 1_500_000 µs → 1.5s.
        push_u32(&mut b, 0x0000_0006);
        push_u32(&mut b, 36);
        push_u32(&mut b, 0); // interface id
        push_u32(&mut b, 0); // ts high
        push_u32(&mut b, 1_500_000); // ts low
        push_u32(&mut b, 4); // caplen
        push_u32(&mut b, 4); // origlen
        b.extend_from_slice(&[0, 0, 0, 0]); // data (4 bytes, already aligned)
        push_u32(&mut b, 36);
        b
    }

    /// A real Ethernet/IPv4/UDP frame: 1.2.3.4 → 5.6.7.8, proto 17.
    fn build_eth_ipv4_udp() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xff; 6]); // dst MAC
        f.extend_from_slice(&[0x11; 6]); // src MAC
        push_u16_be(&mut f, 0x0800); // ethertype IPv4
                                     // IPv4 header (20 bytes), total_len 30 (20 + 8 UDP + 2 payload).
        f.push(0x45); // version 4, ihl 5
        f.push(0x00); // dscp/ecn
        push_u16_be(&mut f, 30); // total length
        push_u16_be(&mut f, 0); // id
        push_u16_be(&mut f, 0); // flags/frag
        f.push(64); // ttl
        f.push(17); // protocol UDP
        push_u16_be(&mut f, 0); // header checksum (not verified by the slicer)
        f.extend_from_slice(&[1, 2, 3, 4]); // src ip
        f.extend_from_slice(&[5, 6, 7, 8]); // dst ip
                                            // UDP header (8 bytes) + 2 payload.
        push_u16_be(&mut f, 1234); // src port
        push_u16_be(&mut f, 53); // dst port
        push_u16_be(&mut f, 10); // length (8 + 2)
        push_u16_be(&mut f, 0); // checksum
        f.extend_from_slice(b"hi");
        f
    }
    fn push_u16_be(b: &mut Vec<u8>, v: u16) {
        b.extend_from_slice(&v.to_be_bytes());
    }

    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    // ---- tests -----------------------------------------------------------

    #[test]
    fn legacy_pcap_timestamps_and_lengths() {
        let cols = PcapParser
            .parse("c.pcap", &build_legacy_pcap(false))
            .unwrap();
        let ts = col(&cols, "timestamp");
        assert_eq!(ts.ty, ColType::Float);
        assert_eq!(ts.cells, vec![Value::Float(1000.0), Value::Float(1001.5)]);
        // length is the original length; caplen the captured (truncated) length.
        assert_eq!(
            col(&cols, "length").cells,
            vec![Value::Int(4), Value::Int(60)]
        );
        assert_eq!(
            col(&cols, "caplen").cells,
            vec![Value::Int(4), Value::Int(4)]
        );
    }

    #[test]
    fn nanosecond_precision_scales_the_fraction() {
        let cols = PcapParser
            .parse("c.pcap", &build_legacy_pcap(true))
            .unwrap();
        // 1001 s + 500_000_000 ns = 1001.5 s (vs the µs interpretation).
        assert_eq!(col(&cols, "timestamp").cells[1], Value::Float(1001.5));
    }

    #[test]
    fn pcapng_enhanced_packet_decodes() {
        let cols = PcapParser.parse("c.pcapng", &build_pcapng()).unwrap();
        assert_eq!(col(&cols, "timestamp").cells, vec![Value::Float(1.5)]);
        assert_eq!(col(&cols, "length").cells, vec![Value::Int(4)]);
    }

    #[test]
    fn add_l3_decodes_ethernet_ipv4() {
        let mut row = BTreeMap::new();
        add_l3(Linktype::ETHERNET, &build_eth_ipv4_udp(), &mut row);
        assert_eq!(row.get("src_ip"), Some(&Value::Str("1.2.3.4".into())));
        assert_eq!(row.get("dst_ip"), Some(&Value::Str("5.6.7.8".into())));
        assert_eq!(row.get("ip_proto"), Some(&Value::Int(17))); // UDP
    }

    /// An IPv6/UDP frame (no Ethernet): ::1 → ::2, next-header 17.
    fn build_ipv6_udp() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, traffic class, flow label
        push_u16_be(&mut f, 10); // payload length (8 UDP + 2)
        f.push(17); // next header UDP
        f.push(64); // hop limit
        f.extend_from_slice(&[0; 15]);
        f.push(1); // src ::1
        f.extend_from_slice(&[0; 15]);
        f.push(2); // dst ::2
        push_u16_be(&mut f, 1234);
        push_u16_be(&mut f, 53);
        push_u16_be(&mut f, 10);
        push_u16_be(&mut f, 0);
        f.extend_from_slice(b"hi");
        f
    }

    #[test]
    fn add_l3_decodes_raw_ipv4_via_from_ip() {
        // Raw-IP link types (e.g. 228) take the from_ip path, no Ethernet header.
        let frame = build_eth_ipv4_udp();
        let ip_only = &frame[14..]; // strip the 14-byte Ethernet header
        let mut row = BTreeMap::new();
        add_l3(Linktype(228), ip_only, &mut row); // LINKTYPE_IPV4
        assert_eq!(row.get("src_ip"), Some(&Value::Str("1.2.3.4".into())));
        assert_eq!(row.get("ip_proto"), Some(&Value::Int(17)));
    }

    #[test]
    fn add_l3_decodes_ipv6() {
        let mut row = BTreeMap::new();
        add_l3(Linktype(101), &build_ipv6_udp(), &mut row); // RAW; version nibble selects v6
        assert_eq!(row.get("src_ip"), Some(&Value::Str("::1".into())));
        assert_eq!(row.get("dst_ip"), Some(&Value::Str("::2".into())));
        assert_eq!(row.get("ip_proto"), Some(&Value::Int(17))); // next header
    }

    #[test]
    fn add_l3_skips_unsupported_and_undecodable() {
        // Unknown link type → no L3 columns.
        let mut row = BTreeMap::new();
        add_l3(Linktype(999), &build_eth_ipv4_udp(), &mut row);
        assert!(row.is_empty());
        // Ethernet link type but garbage/too-short data → no L3 columns.
        let mut row2 = BTreeMap::new();
        add_l3(Linktype::ETHERNET, &[0, 1, 2], &mut row2);
        assert!(row2.is_empty());
    }

    #[test]
    fn end_to_end_l3_columns_present_for_a_real_frame() {
        // A legacy pcap whose single packet is a full Ethernet/IPv4/UDP frame.
        let frame = build_eth_ipv4_udp();
        let mut b = Vec::new();
        push_u32(&mut b, 0xa1b2_c3d4);
        push_u16(&mut b, 2);
        push_u16(&mut b, 4);
        push_u32(&mut b, 0);
        push_u32(&mut b, 0);
        push_u32(&mut b, 65535);
        push_u32(&mut b, 1);
        push_u32(&mut b, 7); // ts_sec
        push_u32(&mut b, 0);
        push_u32(&mut b, frame.len() as u32);
        push_u32(&mut b, frame.len() as u32);
        b.extend_from_slice(&frame);

        let cols = PcapParser.parse("c.pcap", &b).unwrap();
        assert_eq!(col(&cols, "src_ip").cells[0], Value::Str("1.2.3.4".into()));
        assert_eq!(col(&cols, "ip_proto").cells[0], Value::Int(17));
        assert_eq!(col(&cols, "timestamp").cells[0], Value::Float(7.0));
    }

    #[test]
    fn malformed_input_errors() {
        assert!(matches!(
            PcapParser.parse("c.pcap", b"this is not a capture"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_each_magic() {
        assert_eq!(PcapParser.sniff(&build_legacy_pcap(false)), Some(MAGIC));
        assert_eq!(PcapParser.sniff(&build_legacy_pcap(true)), Some(MAGIC));
        assert_eq!(PcapParser.sniff(&build_pcapng()), Some(MAGIC));
        assert_eq!(
            PcapParser.sniff(&[0xa1, 0xb2, 0xc3, 0xd4, 0, 0]),
            Some(MAGIC)
        ); // BE µs
        assert_eq!(PcapParser.sniff(b"PAR1...."), None); // parquet
        assert_eq!(PcapParser.sniff(b"\x00\x01\x02"), None); // too short
        assert_eq!(PcapParser.sniff(b"{\"a\":1}"), None);
    }

    #[test]
    fn claims_pcap_extensions() {
        assert_eq!(PcapParser.extensions(), &["pcap", "pcapng", "cap"]);
    }

    #[test]
    fn resolves_by_extension_and_magic() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("dump.pcap", b"zz").unwrap().id(), "pcap");
        assert_eq!(reg.resolve("dump.pcapng", b"zz").unwrap().id(), "pcap");
        assert_eq!(
            reg.resolve("-", &build_legacy_pcap(false)).unwrap().id(),
            "pcap"
        );
    }
}
