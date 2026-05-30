//! Delimited text parsers: CSV and TSV.
//!
//! Both share one reader; they differ only in the delimiter and their sniff.
//! CSV is the universal fallback — any leftover text is treated as
//! comma-delimited — so it claims the lowest confidence.

use crate::infer;
use crate::parser::{Confidence, FormatParser, FALLBACK, TEXT};
use ax_core::{AxError, Column, Value};

/// Reads delimited text with a header row. Field count is normalized to the
/// header width: short rows pad with [`Value::Null`], long rows truncate.
fn read_delimited(bytes: &[u8], delim: u8, id: &str) -> Result<Vec<Column>, AxError> {
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .has_headers(true)
        .from_reader(bytes);

    let err = |e: csv::Error| AxError::Parse {
        format: id.to_string(),
        message: e.to_string(),
    };

    let headers = rdr
        .headers()
        .map_err(err)?
        .iter()
        .map(|h| h.to_string())
        .collect::<Vec<_>>();

    let mut cols: Vec<Vec<Value>> = vec![Vec::new(); headers.len()];
    for rec in rdr.records() {
        let rec = rec.map_err(err)?;
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

/// True if a tab appears before any comma on `line` (or a tab with no comma) —
/// the signal that a stream is tab- rather than comma-delimited.
///
/// `t` and `c` are byte offsets of distinct characters, so they are never
/// equal; `<` is the only meaningful comparison (its `<=` mutant is therefore
/// equivalent — see `.cargo/mutants.toml`).
fn tab_before_comma(line: &str) -> bool {
    match (line.find('\t'), line.find(',')) {
        (Some(t), Some(c)) => t < c,
        (Some(_), None) => true,
        _ => false,
    }
}

/// The first non-empty trimmed line of a UTF-8 stream that isn't JSON-shaped.
/// Returns `None` for binary, empty, or `[`/`{`-leading content.
fn tabular_first_line(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let trimmed = text.trim_start();
    let first = trimmed.chars().next()?;
    if first == '[' || first == '{' {
        return None;
    }
    trimmed.lines().next()
}

#[derive(Debug, Default, Clone)]
pub struct CsvParser;

impl FormatParser for CsvParser {
    fn id(&self) -> &'static str {
        "csv"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["csv"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        // Fallback: claim any non-JSON UTF-8 text at the lowest confidence.
        tabular_first_line(bytes).map(|_| FALLBACK)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        read_delimited(bytes, b',', self.id())
    }
}

#[derive(Debug, Default, Clone)]
pub struct TsvParser;

impl FormatParser for TsvParser {
    fn id(&self) -> &'static str {
        "tsv"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tsv", "tab"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        tabular_first_line(bytes)
            .filter(|l| tab_before_comma(l))
            .map(|_| TEXT)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        read_delimited(bytes, b'\t', self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    #[test]
    fn tab_before_comma_logic() {
        assert!(tab_before_comma("a\tb,c")); // tab first
        assert!(tab_before_comma("a\tb\tc")); // tab, no comma
        assert!(!tab_before_comma("a,b\tc")); // comma first
        assert!(!tab_before_comma("a,b,c")); // no tab
    }

    #[test]
    fn csv_roundtrip_types_and_nulls() {
        let cols = CsvParser.parse("t.csv", b"a,b\n1,x\n2,\n3,z").unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].ty, ColType::Int);
        assert_eq!(cols[1].null_count(), 1);
    }

    #[test]
    fn ragged_csv_pads_and_truncates() {
        let cols = CsvParser.parse("t.csv", b"a,b\n1\n2,3,4").unwrap();
        assert_eq!(cols[1].cells[0], Value::Null); // short row padded
        assert_eq!(cols[0].len(), 2); // long row truncated to header width
    }

    #[test]
    fn tsv_parses_tab_delimited() {
        let cols = TsvParser.parse("t.tsv", b"a\tb\n1\t2").unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].ty, ColType::Int);
    }

    #[test]
    fn sniff_confidences() {
        assert_eq!(CsvParser.sniff(b"a,b\n1,2"), Some(FALLBACK));
        assert_eq!(TsvParser.sniff(b"a\tb\n1\t2"), Some(TEXT));
        assert_eq!(TsvParser.sniff(b"a,b\n1,2"), None); // no tab → not tsv
        assert_eq!(CsvParser.sniff(b"[1,2]"), None); // JSON-shaped → not csv
        assert_eq!(CsvParser.sniff(&[0xff, 0xfe]), None); // binary → not csv
    }
}
