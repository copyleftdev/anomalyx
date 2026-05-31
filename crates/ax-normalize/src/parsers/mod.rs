//! Built-in format parsers — one module per format. Adding a format is two
//! steps: add a module here, and add one `register(...)` line in
//! [`default_registry`]. Nothing else in the crate changes.

use crate::parser::ParserRegistry;

pub mod accesslog;
pub mod auditd;
pub mod cef;
pub mod cloudtrail;
pub mod delimited;
pub mod eve;
#[cfg(feature = "evtx")]
pub mod evtx;
pub mod journal;
pub mod json;
pub mod logfmt;
pub mod ndjson;
pub mod osquery;
pub mod otlp;
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod prometheus;
pub mod syslog;
pub mod toml;
pub mod yaml;
pub mod zeek;

#[cfg(feature = "polars")]
pub mod columnar;

pub use accesslog::AccessLogParser;
pub use auditd::AuditdParser;
pub use cef::{CefParser, LeefParser};
pub use cloudtrail::CloudTrailParser;
pub use delimited::{CsvParser, TsvParser};
pub use eve::EveParser;
#[cfg(feature = "evtx")]
pub use evtx::EvtxParser;
pub use journal::JournalParser;
pub use json::JsonParser;
pub use logfmt::LogfmtParser;
pub use ndjson::NdjsonParser;
pub use osquery::OsqueryParser;
pub use otlp::OtlpParser;
#[cfg(feature = "pcap")]
pub use pcap::PcapParser;
pub use prometheus::PrometheusParser;
pub use syslog::SyslogParser;
pub use toml::{IniParser, TomlParser};
pub use yaml::YamlParser;
pub use zeek::ZeekParser;

#[cfg(feature = "polars")]
pub use columnar::{ArrowParser, ParquetParser};

/// The default parser set. Registration order is the deterministic tie-break
/// for content sniffing: binary magic first, then the more specific text shapes
/// (NDJSON before JSON, TSV before CSV), then the CSV fallback.
pub fn default_registry() -> ParserRegistry {
    let mut r = ParserRegistry::new();
    register_binary(&mut r);
    // EVTX is a binary format detected by its `ElfFile\0` magic; group it with the
    // other magic-detected binary readers, ahead of the text shapes.
    #[cfg(feature = "evtx")]
    r.register(Box::new(EvtxParser));
    #[cfg(feature = "pcap")]
    r.register(Box::new(PcapParser));
    // OTLP before NDJSON: a compact single-object OTLP doc must win the
    // `resourceSpans` signature before any JSON-line heuristic sees it.
    r.register(Box::new(OtlpParser));
    r.register(Box::new(CloudTrailParser));
    // EVE and Journal before NDJSON: both are NDJSON dialects, so their content
    // signatures must claim them before the generic NDJSON shape does.
    r.register(Box::new(EveParser));
    r.register(Box::new(JournalParser));
    r.register(Box::new(OsqueryParser));
    r.register(Box::new(NdjsonParser));
    r.register(Box::new(ZeekParser));
    r.register(Box::new(LogfmtParser));
    r.register(Box::new(AccessLogParser));
    r.register(Box::new(SyslogParser));
    r.register(Box::new(CefParser));
    r.register(Box::new(LeefParser));
    r.register(Box::new(AuditdParser));
    r.register(Box::new(PrometheusParser));
    r.register(Box::new(JsonParser));
    r.register(Box::new(YamlParser));
    r.register(Box::new(TomlParser));
    r.register(Box::new(IniParser));
    r.register(Box::new(TsvParser));
    r.register(Box::new(CsvParser));
    r
}

/// Binary columnar parsers register only with the `polars` feature. Without it,
/// a Parquet/Arrow file resolves to no parser and is reported as an unknown
/// format — the build genuinely cannot read it.
fn register_binary(r: &mut ParserRegistry) {
    #[cfg(feature = "polars")]
    {
        r.register(Box::new(ParquetParser));
        r.register(Box::new(ArrowParser));
    }
    #[cfg(not(feature = "polars"))]
    {
        let _ = r;
    }
}
