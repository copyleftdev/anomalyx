//! # ax-normalize — any corpus → one [`RecordSet`]
//!
//! The article's normalization promise: *"given any corpus of information
//! regardless of its format, we'll normalize it."* This crate maps recognized
//! text formats (CSV, TSV, NDJSON, JSON) onto the engine-independent
//! [`RecordSet`] from `ax-core`. Binary columnar formats (Parquet, Arrow IPC)
//! land behind this same boundary in the Polars-backed slice — detectors never
//! see the difference.
//!
//! Normalization is deterministic: column order is stable (header order for
//! tabular input, sorted key-union for JSON), and absence is explicit — a key
//! missing from one JSON row becomes [`ax_core::Value::Null`], never a guess.

use ax_core::{AxError, Column, RecordSet, Value};
use std::collections::BTreeMap;

#[cfg(feature = "polars")]
pub mod binary;
pub mod format;
pub mod infer;

pub use format::Format;

/// Reads a binary columnar format (Parquet/Arrow) into columns. Behind the
/// `polars` feature; without it, binary formats fail cleanly (honest absence)
/// rather than the crate silently mis-handling them.
fn read_binary(fmt: Format, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
    #[cfg(feature = "polars")]
    {
        binary::read(fmt, bytes)
    }
    #[cfg(not(feature = "polars"))]
    {
        let _ = bytes;
        Err(AxError::Config(format!(
            "{} requires the 'polars' feature, which was not built",
            fmt.token()
        )))
    }
}

/// Normalizes `bytes` from logical `source` into a [`RecordSet`], resolving the
/// format by extension then content sniff.
pub fn normalize(source: &str, bytes: &[u8]) -> Result<RecordSet, AxError> {
    let fmt = Format::resolve(source, bytes)?;
    normalize_as(source, bytes, fmt)
}

/// Normalizes with an explicit format (skips detection).
pub fn normalize_as(source: &str, bytes: &[u8], fmt: Format) -> Result<RecordSet, AxError> {
    let columns = match fmt {
        Format::Csv => read_delimited(bytes, b',', fmt)?,
        Format::Tsv => read_delimited(bytes, b'\t', fmt)?,
        Format::Ndjson => read_ndjson(bytes, fmt)?,
        Format::Json => read_json(bytes, fmt)?,
        Format::Parquet | Format::Arrow => read_binary(fmt, bytes)?,
    };
    Ok(RecordSet::new(source, fmt.token(), columns))
}

/// Reads CSV/TSV with a header row. Field count is normalized to the header
/// width: short rows pad with [`Value::Null`], long rows truncate.
fn read_delimited(bytes: &[u8], delim: u8, fmt: Format) -> Result<Vec<Column>, AxError> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .has_headers(true)
        .from_reader(bytes);

    let headers = rdr
        .headers()
        .map_err(|e| parse_err(fmt, e))?
        .iter()
        .map(|h| h.to_string())
        .collect::<Vec<_>>();

    let mut cols: Vec<Vec<Value>> = vec![Vec::new(); headers.len()];
    for rec in rdr.records() {
        let rec = rec.map_err(|e| parse_err(fmt, e))?;
        for (i, col) in cols.iter_mut().enumerate() {
            match rec.get(i) {
                Some(field) => col.push(infer::infer_scalar(field)),
                None => col.push(Value::Null),
            }
        }
    }

    Ok(headers
        .into_iter()
        .zip(cols)
        .map(|(name, cells)| Column::new(name, cells))
        .collect())
}

/// Reads newline-delimited JSON. Each non-empty line is one record; scalar or
/// array lines are placed under a synthetic `value` column.
fn read_ndjson(bytes: &[u8], fmt: Format) -> Result<Vec<Column>, AxError> {
    let text = std::str::from_utf8(bytes).map_err(|e| parse_err(fmt, e))?;
    let mut builder = TableBuilder::new();
    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let val: serde_json::Value = serde_json::from_str(line).map_err(|e| AxError::Parse {
            format: fmt.token().to_string(),
            message: format!("line {}: {e}", lineno + 1),
        })?;
        builder.push_value(val);
    }
    Ok(builder.finish())
}

/// Reads a single JSON document: an array of records, a lone object (one row),
/// or a scalar/array (one `value` cell).
fn read_json(bytes: &[u8], fmt: Format) -> Result<Vec<Column>, AxError> {
    let val: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| parse_err(fmt, e))?;
    let mut builder = TableBuilder::new();
    match val {
        serde_json::Value::Array(items) => {
            for item in items {
                builder.push_value(item);
            }
        }
        other => builder.push_value(other),
    }
    Ok(builder.finish())
}

const VALUE_COL: &str = "value";

/// Accumulates JSON records into columns with a stable, sorted key-union order.
/// Missing keys fill with [`Value::Null`] so every column ends equal length.
struct TableBuilder {
    order: Vec<String>,
    index: BTreeMap<String, usize>,
    cols: Vec<Vec<Value>>,
    rows: usize,
}

impl TableBuilder {
    fn new() -> Self {
        TableBuilder {
            order: Vec::new(),
            index: BTreeMap::new(),
            cols: Vec::new(),
            rows: 0,
        }
    }

    /// Ensures a column exists, back-filling it with `Null` for prior rows.
    fn ensure(&mut self, name: &str) -> usize {
        if let Some(&i) = self.index.get(name) {
            return i;
        }
        let i = self.order.len();
        self.order.push(name.to_string());
        self.index.insert(name.to_string(), i);
        self.cols.push(vec![Value::Null; self.rows]);
        i
    }

    /// Adds one record. Objects contribute their fields; anything else goes to
    /// the synthetic `value` column.
    fn push_value(&mut self, val: serde_json::Value) {
        let mut row: BTreeMap<String, Value> = BTreeMap::new();
        match val {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    row.insert(k, infer::json_to_value(&v));
                }
            }
            other => {
                row.insert(VALUE_COL.to_string(), infer::json_to_value(&other));
            }
        }
        for k in row.keys() {
            self.ensure(k);
        }
        for (name, &i) in &self.index {
            let cell = row.remove(name).unwrap_or(Value::Null);
            self.cols[i].push(cell);
        }
        self.rows += 1;
    }

    fn finish(self) -> Vec<Column> {
        self.order
            .into_iter()
            .zip(self.cols)
            .map(|(name, cells)| Column::new(name, cells))
            .collect()
    }
}

fn parse_err(fmt: Format, e: impl std::fmt::Display) -> AxError {
    AxError::Parse {
        format: fmt.token().to_string(),
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    #[test]
    fn csv_roundtrip_types_and_nulls() {
        let rs = normalize("t.csv", b"a,b\n1,x\n2,\n3,z").unwrap();
        assert_eq!(rs.width(), 2);
        assert_eq!(rs.rows(), 3);
        let a = rs.column("a").unwrap();
        assert_eq!(a.ty, ColType::Int);
        let b = rs.column("b").unwrap();
        assert_eq!(b.null_count(), 1);
    }

    #[test]
    fn ndjson_key_union_pads_missing() {
        let rs = normalize("-", b"{\"a\":1}\n{\"a\":2,\"b\":9}\n").unwrap();
        assert_eq!(rs.rows(), 2);
        let b = rs.column("b").unwrap();
        // first row had no `b`
        assert_eq!(b.null_count(), 1);
    }

    #[test]
    fn json_array_of_objects() {
        let rs = normalize("d.json", br#"[{"x":10},{"x":20},{"x":30}]"#).unwrap();
        assert_eq!(rs.rows(), 3);
        assert_eq!(rs.column("x").unwrap().ty, ColType::Int);
    }

    #[test]
    fn json_scalar_goes_to_value_column() {
        let rs = normalize("d.json", b"[1,2,3]").unwrap();
        assert_eq!(rs.column("value").unwrap().numeric(), vec![1.0, 2.0, 3.0]);
    }

    #[test]
    fn unknown_format_errors() {
        assert!(normalize("-", &[0x00, 0x01, 0x02, 0xff]).is_err());
    }

    #[test]
    fn ragged_csv_pads_and_truncates() {
        let rs = normalize("t.csv", b"a,b\n1\n2,3,4").unwrap();
        assert_eq!(rs.rows(), 2);
        assert_eq!(rs.column("b").unwrap().cells[0], Value::Null);
    }
}
