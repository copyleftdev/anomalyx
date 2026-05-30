//! Binary columnar parsers (Parquet, Arrow IPC) via the Polars/Arrow backbone.
//!
//! This is the *only* module that knows Polars exists. Each reader produces a
//! Polars `DataFrame` and lowers it to engine-independent [`Column`]s — so no
//! Polars type ever reaches a detector, the envelope, or the contract. Cell
//! values map into the same closed [`Value`] set as the text parsers; logical
//! types Polars exposes but anomalyx doesn't model are preserved as their
//! string form rather than guessed at.

use crate::parser::{Confidence, FormatParser, MAGIC};
use ax_core::{AxError, Column, Value};
use polars::prelude::*;
use std::io::Cursor;

/// Lowers a Polars `DataFrame` to `Column`s, preserving column order.
fn df_to_columns(df: &DataFrame) -> Vec<Column> {
    df.columns()
        .iter()
        .map(|col| {
            let series = col.as_materialized_series();
            let cells: Vec<Value> = series.iter().map(any_value_to_value).collect();
            Column::new(col.name().as_str(), cells)
        })
        .collect()
}

/// Maps one Polars `AnyValue` into the closed [`Value`] set. Integer widths fold
/// to `i64`; floats to `f64` (non-finite → `Null`); strings pass through; any
/// other logical type is preserved as its display string (honest, not dropped).
fn any_value_to_value(av: AnyValue) -> Value {
    match av {
        AnyValue::Null => Value::Null,
        AnyValue::Boolean(b) => Value::Bool(b),
        AnyValue::Int8(v) => Value::Int(v as i64),
        AnyValue::Int16(v) => Value::Int(v as i64),
        AnyValue::Int32(v) => Value::Int(v as i64),
        AnyValue::Int64(v) => Value::Int(v),
        AnyValue::UInt8(v) => Value::Int(v as i64),
        AnyValue::UInt16(v) => Value::Int(v as i64),
        AnyValue::UInt32(v) => Value::Int(v as i64),
        // u64 can exceed i64; keep the exact value as a string rather than wrap.
        AnyValue::UInt64(v) => match i64::try_from(v) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Str(v.to_string()),
        },
        AnyValue::Float32(v) => finite_float(v as f64),
        AnyValue::Float64(v) => finite_float(v),
        AnyValue::String(s) => Value::Str(s.to_string()),
        AnyValue::StringOwned(s) => Value::Str(s.to_string()),
        other => Value::Str(other.to_string()),
    }
}

/// A finite float becomes `Float`; NaN/±∞ become `Null` (honest absence).
fn finite_float(f: f64) -> Value {
    if f.is_finite() {
        Value::Float(f)
    } else {
        Value::Null
    }
}

fn parse_err(id: &str, e: impl std::fmt::Display) -> AxError {
    AxError::Parse {
        format: id.to_string(),
        message: e.to_string(),
    }
}

#[derive(Debug, Default, Clone)]
pub struct ParquetParser;

impl FormatParser for ParquetParser {
    fn id(&self) -> &'static str {
        "parquet"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["parquet", "pq"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        // Parquet files begin (and end) with the 4-byte magic "PAR1".
        bytes.starts_with(b"PAR1").then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let df = ParquetReader::new(Cursor::new(bytes.to_vec()))
            .finish()
            .map_err(|e| parse_err(self.id(), e))?;
        Ok(df_to_columns(&df))
    }
}

#[derive(Debug, Default, Clone)]
pub struct ArrowParser;

impl FormatParser for ArrowParser {
    fn id(&self) -> &'static str {
        "arrow"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["arrow", "ipc", "feather"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        // Arrow IPC files begin with "ARROW1".
        bytes.starts_with(b"ARROW1").then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let df = IpcReader::new(Cursor::new(bytes.to_vec()))
            .finish()
            .map_err(|e| parse_err(self.id(), e))?;
        Ok(df_to_columns(&df))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    fn parquet_bytes(df: &mut DataFrame) -> Vec<u8> {
        let mut buf = Vec::new();
        ParquetWriter::new(&mut buf).finish(df).unwrap();
        buf
    }
    fn arrow_bytes(df: &mut DataFrame) -> Vec<u8> {
        let mut buf = Vec::new();
        IpcWriter::new(&mut buf).finish(df).unwrap();
        buf
    }

    #[test]
    fn any_value_mapping_is_exact() {
        assert_eq!(any_value_to_value(AnyValue::Null), Value::Null);
        assert_eq!(
            any_value_to_value(AnyValue::Boolean(true)),
            Value::Bool(true)
        );
        assert_eq!(any_value_to_value(AnyValue::Int32(5)), Value::Int(5));
        assert_eq!(any_value_to_value(AnyValue::Int64(-9)), Value::Int(-9));
        assert_eq!(any_value_to_value(AnyValue::UInt8(7)), Value::Int(7));
        assert_eq!(
            any_value_to_value(AnyValue::Float64(1.5)),
            Value::Float(1.5)
        );
        assert_eq!(
            any_value_to_value(AnyValue::String("hi")),
            Value::Str("hi".into())
        );
        // u64 beyond i64::MAX is preserved as a string, not wrapped
        assert_eq!(
            any_value_to_value(AnyValue::UInt64(u64::MAX)),
            Value::Str(u64::MAX.to_string())
        );
    }

    #[test]
    fn non_finite_float_becomes_null() {
        assert_eq!(finite_float(f64::NAN), Value::Null);
        assert_eq!(finite_float(f64::INFINITY), Value::Null);
        assert_eq!(finite_float(2.0), Value::Float(2.0));
    }

    #[test]
    fn parquet_roundtrips_to_columns() {
        let mut df = df!["amount" => [10i64, 20, 30], "tier" => ["a", "b", "c"]].unwrap();
        let cols = ParquetParser
            .parse("d.parquet", &parquet_bytes(&mut df))
            .unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].name, "amount");
        assert_eq!(cols[0].ty, ColType::Int);
        assert_eq!(cols[0].numeric(), vec![10.0, 20.0, 30.0]);
        assert_eq!(cols[1].ty, ColType::Str);
    }

    #[test]
    fn arrow_roundtrips_to_columns() {
        let mut df = df!["x" => [1.5f64, 2.5, 3.5], "ok" => [true, false, true]].unwrap();
        let cols = ArrowParser.parse("d.arrow", &arrow_bytes(&mut df)).unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].ty, ColType::Float);
        assert_eq!(cols[1].ty, ColType::Bool);
    }

    #[test]
    fn nulls_survive_the_roundtrip() {
        let s = Series::new("v".into(), &[Some(1i64), None, Some(3)]);
        let mut df = DataFrame::new_infer_height(vec![s.into()]).unwrap();
        let cols = ParquetParser
            .parse("d.parquet", &parquet_bytes(&mut df))
            .unwrap();
        assert_eq!(cols[0].null_count(), 1);
    }

    #[test]
    fn corrupt_bytes_fail_cleanly() {
        assert!(matches!(
            ParquetParser.parse("d.parquet", b"PAR1 not really parquet"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_matches_magic() {
        assert_eq!(ParquetParser.sniff(b"PAR1xxxx"), Some(MAGIC));
        assert_eq!(ParquetParser.sniff(b"nope"), None);
        assert_eq!(ArrowParser.sniff(b"ARROW1\x00"), Some(MAGIC));
        assert_eq!(ArrowParser.sniff(b"nope"), None);
    }
}
