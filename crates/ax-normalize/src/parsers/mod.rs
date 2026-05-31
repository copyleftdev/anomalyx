//! Built-in format parsers — one module per format. Adding a format is two
//! steps: add a module here, and add one `register(...)` line in
//! [`default_registry`]. Nothing else in the crate changes.

use crate::parser::ParserRegistry;

pub mod accesslog;
pub mod delimited;
pub mod json;
pub mod logfmt;
pub mod ndjson;
pub mod prometheus;
pub mod zeek;

#[cfg(feature = "polars")]
pub mod columnar;

pub use accesslog::AccessLogParser;
pub use delimited::{CsvParser, TsvParser};
pub use json::JsonParser;
pub use logfmt::LogfmtParser;
pub use ndjson::NdjsonParser;
pub use prometheus::PrometheusParser;
pub use zeek::ZeekParser;

#[cfg(feature = "polars")]
pub use columnar::{ArrowParser, ParquetParser};

/// The default parser set. Registration order is the deterministic tie-break
/// for content sniffing: binary magic first, then the more specific text shapes
/// (NDJSON before JSON, TSV before CSV), then the CSV fallback.
pub fn default_registry() -> ParserRegistry {
    let mut r = ParserRegistry::new();
    register_binary(&mut r);
    r.register(Box::new(NdjsonParser));
    r.register(Box::new(ZeekParser));
    r.register(Box::new(LogfmtParser));
    r.register(Box::new(AccessLogParser));
    r.register(Box::new(PrometheusParser));
    r.register(Box::new(JsonParser));
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
