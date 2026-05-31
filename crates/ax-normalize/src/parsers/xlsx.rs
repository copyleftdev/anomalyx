//! Excel / OpenDocument spreadsheet parser — the universal business handoff.
//!
//! The first worksheet of a workbook (`.xlsx`/`.xls`/`.xlsb`/`.ods`) becomes a
//! RecordSet: the first row is the header (column names), each subsequent row is
//! a record, and every cell maps to the closed [`Value`] set — so all detectors
//! apply with no special-casing. A date/time cell keeps its Excel serial number
//! (numeric, deterministic); blanks and error cells are `Null` (honest absence).
//!
//! Reading is delegated to `calamine` (pure Rust, all four formats). Detected by
//! the ZIP magic plus an `xl/` or OpenDocument-spreadsheet marker; extensions
//! `.xlsx`/`.xls`/`.xlsb`/`.ods`. Behind the default-on `xlsx` feature.

use crate::parser::{Confidence, FormatParser, MAGIC};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use calamine::{open_workbook_auto_from_rs, Data, Reader};
use std::collections::BTreeMap;
use std::io::Cursor;

#[derive(Debug, Default, Clone)]
pub struct XlsxParser;

/// True if `needle` appears anywhere in `haystack`.
fn contains_seq(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Maps a calamine cell to the closed [`Value`] set.
fn data_to_value(cell: &Data) -> Value {
    match cell {
        Data::Int(i) => Value::Int(*i),
        Data::Float(f) => {
            if f.is_finite() {
                Value::Float(*f)
            } else {
                Value::Null
            }
        }
        Data::String(s) => Value::Str(s.clone()),
        Data::Bool(b) => Value::Bool(*b),
        // Keep the Excel serial number — numeric and deterministic.
        Data::DateTime(dt) => Value::Float(dt.as_f64()),
        Data::DateTimeIso(s) | Data::DurationIso(s) => Value::Str(s.clone()),
        Data::Error(_) | Data::Empty => Value::Null,
    }
}

/// The column name for a header cell: a non-empty string cell verbatim, else a
/// positional `col{index}`.
fn header_name(cell: &Data, index: usize) -> String {
    match cell {
        Data::String(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => format!("col{index}"),
    }
}

impl XlsxParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for XlsxParser {
    fn id(&self) -> &'static str {
        "xlsx"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["xlsx", "xls", "xlsb", "ods"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        if !bytes.starts_with(b"PK\x03\x04") {
            return None; // not a ZIP (xls's OLE2 magic is handled by extension)
        }
        // A ZIP that is specifically a spreadsheet: xlsx/xlsb have an `xl/` part,
        // ODS declares the OpenDocument-spreadsheet mimetype. (A docx/jar/plain
        // zip has neither, so it is not claimed.)
        (contains_seq(bytes, b"xl/") || contains_seq(bytes, b"opendocument.spreadsheet"))
            .then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let mut workbook =
            open_workbook_auto_from_rs(Cursor::new(bytes.to_vec())).map_err(|e| self.err(e))?;
        let sheet = workbook
            .sheet_names()
            .first()
            .cloned()
            .ok_or_else(|| self.err("workbook has no sheets"))?;
        let range = workbook.worksheet_range(&sheet).map_err(|e| self.err(e))?;

        let mut rows = range.rows();
        let Some(header) = rows.next() else {
            return Ok(Vec::new()); // empty sheet → no columns
        };
        let names: Vec<String> = header
            .iter()
            .enumerate()
            .map(|(i, cell)| header_name(cell, i))
            .collect();

        let mut builder = TableBuilder::new();
        for row in rows {
            let mut record: BTreeMap<String, Value> = BTreeMap::new();
            for (name, cell) in names.iter().zip(row) {
                record.insert(name.clone(), data_to_value(cell));
            }
            builder.push_row(record);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calamine::{CellErrorType, ExcelDateTime, ExcelDateTimeType};
    use rust_xlsxwriter::Workbook;

    /// Writes a tiny .xlsx in-memory: header + two records (string / number / bool).
    fn build_xlsx() -> Vec<u8> {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        for (c, h) in ["name", "score", "active"].iter().enumerate() {
            ws.write(0, c as u16, *h).unwrap();
        }
        ws.write(1, 0, "alice").unwrap();
        ws.write(1, 1, 95).unwrap();
        ws.write(1, 2, true).unwrap();
        ws.write(2, 0, "bob").unwrap();
        ws.write(2, 1, 42.5).unwrap();
        ws.write(2, 2, false).unwrap();
        wb.save_to_buffer().unwrap()
    }

    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn roundtrip_first_sheet_to_records() {
        let bytes = build_xlsx();
        let cols = XlsxParser.parse("book.xlsx", &bytes).unwrap();
        assert_eq!(
            col(&cols, "name").cells,
            vec![Value::Str("alice".into()), Value::Str("bob".into())]
        );
        let score = col(&cols, "score");
        assert_eq!(score.numeric(), vec![95.0, 42.5]);
        assert_eq!(
            col(&cols, "active").cells,
            vec![Value::Bool(true), Value::Bool(false)]
        );
    }

    #[test]
    fn data_to_value_units() {
        assert_eq!(data_to_value(&Data::Int(7)), Value::Int(7));
        assert_eq!(data_to_value(&Data::Float(1.5)), Value::Float(1.5));
        assert_eq!(data_to_value(&Data::Float(f64::NAN)), Value::Null); // non-finite → null
        assert_eq!(
            data_to_value(&Data::String("x".into())),
            Value::Str("x".into())
        );
        assert_eq!(data_to_value(&Data::Bool(true)), Value::Bool(true));
        assert_eq!(data_to_value(&Data::Empty), Value::Null);
        assert_eq!(
            data_to_value(&Data::Error(CellErrorType::Div0)),
            Value::Null
        );
        assert_eq!(
            data_to_value(&Data::DateTimeIso("2021-01-01".into())),
            Value::Str("2021-01-01".into())
        );
        // A date cell keeps its Excel serial number.
        let dt = ExcelDateTime::new(44197.0, ExcelDateTimeType::DateTime, false);
        assert_eq!(data_to_value(&Data::DateTime(dt)), Value::Float(44197.0));
    }

    #[test]
    fn header_name_units() {
        assert_eq!(header_name(&Data::String("score".into()), 1), "score");
        assert_eq!(header_name(&Data::String("  ".into()), 1), "col1"); // blank → positional
        assert_eq!(header_name(&Data::Empty, 2), "col2");
        assert_eq!(header_name(&Data::Int(5), 0), "col0"); // non-string → positional
    }

    #[test]
    fn malformed_input_errors() {
        assert!(matches!(
            XlsxParser.parse("book.xlsx", b"not a spreadsheet"),
            Err(AxError::Parse { .. })
        ));
        // ZIP magic but not a valid workbook.
        assert!(matches!(
            XlsxParser.parse("book.xlsx", b"PK\x03\x04 garbage"),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_zip_plus_spreadsheet_marker() {
        assert_eq!(XlsxParser.sniff(&build_xlsx()), Some(MAGIC));
        // A ZIP that is not a spreadsheet (e.g. a .docx has `word/`, not `xl/`).
        assert_eq!(XlsxParser.sniff(b"PK\x03\x04....word/document.xml"), None);
        assert_eq!(XlsxParser.sniff(b"not a zip"), None);
        assert_eq!(XlsxParser.sniff(b"PK"), None); // too short for the magic
    }

    #[test]
    fn contains_seq_units() {
        assert!(contains_seq(b"hello xl/ world", b"xl/"));
        assert!(!contains_seq(b"hello world", b"xl/"));
        assert!(!contains_seq(b"ab", b"abc")); // needle longer than haystack
    }

    #[test]
    fn claims_spreadsheet_extensions() {
        assert_eq!(XlsxParser.extensions(), &["xlsx", "xls", "xlsb", "ods"]);
    }

    #[test]
    fn resolves_by_extension_and_magic() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("book.xlsx", b"zz").unwrap().id(), "xlsx");
        assert_eq!(reg.resolve("sheet.ods", b"zz").unwrap().id(), "xlsx");
        assert_eq!(reg.resolve("-", &build_xlsx()).unwrap().id(), "xlsx");
    }
}
