//! # ax-normalize — any corpus → one [`RecordSet`]
//!
//! The article's normalization promise: *"given any corpus of information
//! regardless of its format, we'll normalize it."* This crate maps every
//! recognized format onto the engine-independent [`RecordSet`] from `ax-core`,
//! so detectors never see the difference between a CSV and a Parquet file.
//!
//! Formats are **plugins**: each is an independent [`FormatParser`] (one file
//! under [`parsers`]), resolved by a [`ParserRegistry`] via file extension then
//! content sniff. Adding a format is a new file plus one registration line —
//! see [`parsers::default_registry`]. Binary columnar formats (Parquet, Arrow
//! IPC) live behind the default-on `polars` feature.
//!
//! Normalization is deterministic: column order is stable (header order for
//! tabular input, sorted key-union for JSON), and absence is explicit — a key
//! missing from one JSON row becomes [`ax_core::Value::Null`], never a guess.

use ax_core::{AxError, RecordSet};

pub mod infer;
pub mod parser;
pub mod parsers;
pub mod table;

pub use parser::{Confidence, FormatParser, ParserRegistry};

/// Normalizes `bytes` from logical `source` into a [`RecordSet`], resolving the
/// format by extension then content sniff against the default parser registry.
pub fn normalize(source: &str, bytes: &[u8]) -> Result<RecordSet, AxError> {
    ParserRegistry::default().normalize(source, bytes)
}

/// Normalizes with an explicitly chosen format `id` (skips detection).
pub fn normalize_with(id: &str, source: &str, bytes: &[u8]) -> Result<RecordSet, AxError> {
    ParserRegistry::default().normalize_with(id, source, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{ColType, Value};

    #[test]
    fn csv_end_to_end() {
        let rs = normalize("t.csv", b"a,b\n1,x\n2,\n3,z").unwrap();
        assert_eq!(rs.format, "csv");
        assert_eq!(rs.width(), 2);
        assert_eq!(rs.rows(), 3);
        assert_eq!(rs.column("a").unwrap().ty, ColType::Int);
        assert_eq!(rs.column("b").unwrap().null_count(), 1);
    }

    #[test]
    fn ndjson_end_to_end() {
        let rs = normalize("-", b"{\"a\":1}\n{\"a\":2,\"b\":9}\n").unwrap();
        assert_eq!(rs.format, "ndjson");
        assert_eq!(rs.rows(), 2);
        assert_eq!(rs.column("b").unwrap().null_count(), 1);
    }

    #[test]
    fn json_end_to_end() {
        let rs = normalize("d.json", br#"[{"x":10},{"x":20},{"x":30}]"#).unwrap();
        assert_eq!(rs.format, "json");
        assert_eq!(rs.rows(), 3);
        assert_eq!(rs.column("x").unwrap().ty, ColType::Int);
    }

    #[test]
    fn tsv_sniffed_from_content() {
        let rs = normalize("-", b"a\tb\n1\t2\n3\t4").unwrap();
        assert_eq!(rs.format, "tsv");
        assert_eq!(rs.width(), 2);
    }

    #[test]
    fn ragged_csv_pads_and_truncates() {
        let rs = normalize("t.csv", b"a,b\n1\n2,3,4").unwrap();
        assert_eq!(rs.rows(), 2);
        assert_eq!(rs.column("b").unwrap().cells[0], Value::Null);
    }

    #[test]
    fn unknown_format_errors() {
        assert!(matches!(
            normalize("-", &[0x00, 0x01, 0x02, 0xff]),
            Err(AxError::UnknownFormat(_))
        ));
    }

    #[test]
    fn normalize_with_explicit_id() {
        // Force TSV parsing even though the bytes would sniff as CSV.
        let rs = normalize_with("csv", "x", b"a,b\n1,2").unwrap();
        assert_eq!(rs.format, "csv");
        assert!(normalize_with("nonesuch", "x", b"a,b").is_err());
    }

    #[cfg(feature = "polars")]
    #[test]
    fn parquet_routes_through_the_registry() {
        use polars::prelude::*;
        let mut df = df!["a" => [1i64, 2, 3], "b" => [4i64, 5, 6]].unwrap();
        let mut buf = Vec::new();
        ParquetWriter::new(&mut buf).finish(&mut df).unwrap();
        let rs = normalize("t.parquet", &buf).unwrap();
        assert_eq!(rs.format, "parquet");
        assert_eq!(rs.width(), 2);
        assert_eq!(rs.rows(), 3);
    }
}
