//! Built-in format parsers — one module per format. Adding a format is two
//! steps: add a module here, and add one `register(...)` line in
//! [`default_registry`]. Nothing else in the crate changes.

use crate::parser::ParserRegistry;

pub mod accesslog;
pub mod delimited;
pub mod journal;
pub mod json;
pub mod logfmt;
pub mod ndjson;
pub mod otlp;
pub mod prometheus;
pub mod toml;
pub mod yaml;
pub mod zeek;

#[cfg(feature = "polars")]
pub mod columnar;

pub use accesslog::AccessLogParser;
pub use delimited::{CsvParser, TsvParser};
pub use journal::JournalParser;
pub use json::JsonParser;
pub use logfmt::LogfmtParser;
pub use ndjson::NdjsonParser;
pub use otlp::OtlpParser;
pub use prometheus::PrometheusParser;
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
    // OTLP before NDJSON: a compact single-object OTLP doc must win the
    // `resourceSpans` signature before any JSON-line heuristic sees it.
    r.register(Box::new(OtlpParser));
    // Journal before NDJSON: a journald export is NDJSON, so its trusted-field
    // signature must claim it before the generic NDJSON shape does.
    r.register(Box::new(JournalParser));
    r.register(Box::new(NdjsonParser));
    r.register(Box::new(ZeekParser));
    r.register(Box::new(LogfmtParser));
    r.register(Box::new(AccessLogParser));
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
