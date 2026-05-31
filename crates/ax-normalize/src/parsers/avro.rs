//! Avro and ORC parsers — the data-lake siblings of Parquet.
//!
//! Both lower to the same engine-independent [`Column`]s as the Parquet/Arrow
//! parsers, so no library type escapes the contract.
//!
//! - **Avro** (`apache-avro`): each record in the object-container file is a row;
//!   record fields become typed columns. Bytes/fixed → hex `Str`; dates/times →
//!   their integer value; nested records/arrays/maps and decimals are recorded as
//!   `Null` (honest absence — v1 lowers only flat scalar columns).
//! - **ORC** (`orc-rust` → Arrow): the file is read into Arrow batches; each cell
//!   is rendered and type-inferred into the closed [`Value`] set.
//!
//! Detected by their binary magic (`Obj\x01` / `ORC`); extensions `.avro` /
//! `.orc`. Behind the default-on `datalake` feature.

use crate::infer;
use crate::parser::{Confidence, FormatParser, MAGIC};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

/// A finite float becomes `Float`; NaN/±∞ become `Null` (honest absence).
fn finite_float(f: f64) -> Value {
    if f.is_finite() {
        Value::Float(f)
    } else {
        Value::Null
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_err(id: &str, e: impl std::fmt::Display) -> AxError {
    AxError::Parse {
        format: id.to_string(),
        message: e.to_string(),
    }
}

// ----------------------------------------------------------------- Avro -------

use apache_avro::types::Value as AvroValue;

#[derive(Debug, Default, Clone)]
pub struct AvroParser;

/// Maps an Avro value to the closed [`Value`] set.
fn avro_to_value(value: &AvroValue) -> Value {
    match value {
        AvroValue::Null => Value::Null,
        AvroValue::Boolean(b) => Value::Bool(*b),
        AvroValue::Int(i) => Value::Int(i64::from(*i)),
        AvroValue::Long(i) => Value::Int(*i),
        AvroValue::Float(f) => finite_float(f64::from(*f)),
        AvroValue::Double(f) => finite_float(*f),
        AvroValue::String(s) => Value::Str(s.clone()),
        AvroValue::Enum(_, s) => Value::Str(s.clone()),
        AvroValue::Bytes(b) | AvroValue::Fixed(_, b) => Value::Str(hex(b)),
        AvroValue::Union(_, inner) => avro_to_value(inner),
        AvroValue::Date(d) => Value::Int(i64::from(*d)),
        AvroValue::TimeMillis(t) => Value::Int(i64::from(*t)),
        AvroValue::TimeMicros(t)
        | AvroValue::TimestampMillis(t)
        | AvroValue::TimestampMicros(t)
        | AvroValue::TimestampNanos(t)
        | AvroValue::LocalTimestampMillis(t)
        | AvroValue::LocalTimestampMicros(t)
        | AvroValue::LocalTimestampNanos(t) => Value::Int(*t),
        // Records, arrays, maps, decimals, uuids, durations are not flat scalars.
        _ => Value::Null,
    }
}

impl FormatParser for AvroParser {
    fn id(&self) -> &'static str {
        "avro"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["avro"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        // Avro object-container file magic.
        bytes.starts_with(b"Obj\x01").then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let reader = apache_avro::Reader::new(bytes).map_err(|e| parse_err(self.id(), e))?;
        let mut builder = TableBuilder::new();
        for record in reader {
            let value = record.map_err(|e| parse_err(self.id(), e))?;
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            match value {
                AvroValue::Record(fields) => {
                    for (name, field) in fields {
                        row.insert(name, avro_to_value(&field));
                    }
                }
                other => {
                    row.insert("value".to_string(), avro_to_value(&other));
                }
            }
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

// ------------------------------------------------------------------ ORC -------

#[derive(Debug, Default, Clone)]
pub struct OrcParser;

/// Renders one Arrow cell into the closed [`Value`] set (null-aware; the string
/// rendering is type-inferred so numbers/bools become typed columns).
fn orc_cell(array: &dyn arrow::array::Array, row: usize) -> Value {
    if array.is_null(row) {
        return Value::Null;
    }
    match arrow::util::display::array_value_to_string(array, row) {
        Ok(s) => infer::infer_scalar(&s),
        Err(_) => Value::Null,
    }
}

impl FormatParser for OrcParser {
    fn id(&self) -> &'static str {
        "orc"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["orc"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        // ORC files begin with the 3-byte magic "ORC".
        bytes.starts_with(b"ORC").then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let cursor = bytes::Bytes::from(bytes.to_vec());
        let reader = orc_rust::ArrowReaderBuilder::try_new(cursor)
            .map_err(|e| parse_err(self.id(), e))?
            .build();
        let mut builder = TableBuilder::new();
        for batch in reader {
            let batch = batch.map_err(|e| parse_err(self.id(), e))?;
            let schema = batch.schema();
            for row in 0..batch.num_rows() {
                let mut record: BTreeMap<String, Value> = BTreeMap::new();
                for (i, field) in schema.fields().iter().enumerate() {
                    record.insert(
                        field.name().clone(),
                        orc_cell(batch.column(i).as_ref(), row),
                    );
                }
                builder.push_row(record);
            }
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    // ----------------------------------------------------------- Avro -------

    /// Writes a tiny Avro object-container file in-memory (no committed fixture).
    fn build_avro() -> Vec<u8> {
        use apache_avro::{types::Record, Schema, Writer};
        let schema = Schema::parse_str(
            r#"{"type":"record","name":"r","fields":[
                {"name":"id","type":"long"},
                {"name":"host","type":"string"},
                {"name":"score","type":"double"},
                {"name":"ok","type":"boolean"}]}"#,
        )
        .unwrap();
        let mut writer = Writer::new(&schema, Vec::new());
        for (id, host, score, ok) in [(1i64, "a", 9.5f64, true), (2, "b", 3.25, false)] {
            let mut rec = Record::new(writer.schema()).unwrap();
            rec.put("id", id);
            rec.put("host", host);
            rec.put("score", score);
            rec.put("ok", ok);
            writer.append(rec).unwrap();
        }
        writer.into_inner().unwrap()
    }

    #[test]
    fn avro_records_become_typed_rows() {
        let cols = AvroParser.parse("data.avro", &build_avro()).unwrap();
        assert_eq!(col(&cols, "id").ty, ColType::Int);
        assert_eq!(col(&cols, "id").cells, vec![Value::Int(1), Value::Int(2)]);
        assert_eq!(
            col(&cols, "host").cells,
            vec![Value::Str("a".into()), Value::Str("b".into())]
        );
        assert_eq!(col(&cols, "score").numeric(), vec![9.5, 3.25]);
        assert_eq!(
            col(&cols, "ok").cells,
            vec![Value::Bool(true), Value::Bool(false)]
        );
    }

    #[test]
    fn avro_to_value_units() {
        assert_eq!(avro_to_value(&AvroValue::Null), Value::Null);
        assert_eq!(avro_to_value(&AvroValue::Boolean(true)), Value::Bool(true));
        assert_eq!(avro_to_value(&AvroValue::Int(5)), Value::Int(5));
        assert_eq!(avro_to_value(&AvroValue::Long(9)), Value::Int(9));
        assert_eq!(avro_to_value(&AvroValue::Float(1.5)), Value::Float(1.5));
        assert_eq!(avro_to_value(&AvroValue::Double(2.5)), Value::Float(2.5));
        assert_eq!(avro_to_value(&AvroValue::Double(f64::NAN)), Value::Null);
        assert_eq!(
            avro_to_value(&AvroValue::String("x".into())),
            Value::Str("x".into())
        );
        assert_eq!(
            avro_to_value(&AvroValue::Enum(0, "GET".into())),
            Value::Str("GET".into())
        );
        assert_eq!(
            avro_to_value(&AvroValue::Bytes(vec![0x00, 0xab])),
            Value::Str("00ab".into())
        );
        // A union unwraps to its held value (the common nullable shape).
        assert_eq!(
            avro_to_value(&AvroValue::Union(1, Box::new(AvroValue::Long(7)))),
            Value::Int(7)
        );
        assert_eq!(avro_to_value(&AvroValue::Date(19000)), Value::Int(19000));
        assert_eq!(avro_to_value(&AvroValue::TimeMillis(500)), Value::Int(500));
        assert_eq!(
            avro_to_value(&AvroValue::TimestampMillis(1234)),
            Value::Int(1234)
        );
        // Complex/non-scalar values are recorded as absent.
        assert_eq!(avro_to_value(&AvroValue::Array(vec![])), Value::Null);
        assert_eq!(avro_to_value(&AvroValue::Record(vec![])), Value::Null);
    }

    #[test]
    fn avro_malformed_and_sniff() {
        assert!(matches!(
            AvroParser.parse("data.avro", b"not avro"),
            Err(AxError::Parse { .. })
        ));
        assert_eq!(AvroParser.sniff(&build_avro()), Some(MAGIC));
        assert_eq!(AvroParser.sniff(b"Obj\x01...."), Some(MAGIC));
        assert_eq!(AvroParser.sniff(b"ORC"), None);
        assert_eq!(AvroParser.sniff(b"{}"), None);
        assert_eq!(AvroParser.extensions(), &["avro"]);
    }

    // ------------------------------------------------------------ ORC -------

    /// Writes a tiny ORC file in-memory via the orc-rust Arrow writer.
    fn build_orc() -> Vec<u8> {
        use arrow::array::{ArrayRef, Float64Array, Int64Array, StringArray};
        use arrow::record_batch::RecordBatch;
        use std::sync::Arc;

        let batch = RecordBatch::try_from_iter(vec![
            ("id", Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef),
            (
                "host",
                Arc::new(StringArray::from(vec!["a", "b", "c"])) as ArrayRef,
            ),
            (
                "score",
                Arc::new(Float64Array::from(vec![9.5, 3.25, 7.5])) as ArrayRef,
            ),
        ])
        .unwrap();

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut writer = orc_rust::ArrowWriterBuilder::new(&mut buf, batch.schema())
                .try_build()
                .unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
        }
        buf
    }

    #[test]
    fn orc_rows_are_type_inferred() {
        let cols = OrcParser.parse("data.orc", &build_orc()).unwrap();
        assert_eq!(col(&cols, "id").ty, ColType::Int);
        assert_eq!(
            col(&cols, "id").cells,
            vec![Value::Int(1), Value::Int(2), Value::Int(3)]
        );
        assert_eq!(
            col(&cols, "host").cells,
            vec![
                Value::Str("a".into()),
                Value::Str("b".into()),
                Value::Str("c".into())
            ]
        );
        assert_eq!(col(&cols, "score").numeric(), vec![9.5, 3.25, 7.5]);
    }

    #[test]
    fn orc_null_cell() {
        use arrow::array::{ArrayRef, Int64Array};
        use arrow::record_batch::RecordBatch;
        use std::sync::Arc;
        let batch = RecordBatch::try_from_iter(vec![(
            "v",
            Arc::new(Int64Array::from(vec![Some(1), None, Some(3)])) as ArrayRef,
        )])
        .unwrap();
        let mut buf = Vec::new();
        {
            let mut w = orc_rust::ArrowWriterBuilder::new(&mut buf, batch.schema())
                .try_build()
                .unwrap();
            w.write(&batch).unwrap();
            w.close().unwrap();
        }
        let cols = OrcParser.parse("-", &buf).unwrap();
        assert_eq!(col(&cols, "v").cells[1], Value::Null);
    }

    #[test]
    fn orc_malformed_and_sniff() {
        assert!(matches!(
            OrcParser.parse("data.orc", b"not orc at all....."),
            Err(AxError::Parse { .. })
        ));
        assert_eq!(OrcParser.sniff(&build_orc()), Some(MAGIC));
        assert_eq!(OrcParser.sniff(b"ORC....."), Some(MAGIC));
        assert_eq!(OrcParser.sniff(b"Obj\x01"), None);
        assert_eq!(OrcParser.extensions(), &["orc"]);
    }

    #[test]
    fn resolve_by_extension_and_magic() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("x.avro", b"zz").unwrap().id(), "avro");
        assert_eq!(reg.resolve("x.orc", b"zz").unwrap().id(), "orc");
        assert_eq!(reg.resolve("-", &build_avro()).unwrap().id(), "avro");
        assert_eq!(reg.resolve("-", &build_orc()).unwrap().id(), "orc");
    }
}
