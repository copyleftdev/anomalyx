//! The normalized columnar record model — the single shape every input format
//! collapses into, and the only thing detectors ever see.
//!
//! Keeping this engine-independent (no Polars/Arrow types leak in) is what lets
//! the *contract* stay stable while the normalization backend underneath it
//! changes. `ax-normalize` owns the Polars dependency and converts down to this.

use crate::value::{ColType, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One named column with an inferred type and its cells in row order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub ty: ColType,
    pub cells: Vec<Value>,
}

impl Column {
    /// Builds a column from `name` and `cells`, inferring `ty` by folding each
    /// cell's contributed type through [`ColType::unify`].
    pub fn new(name: impl Into<String>, cells: Vec<Value>) -> Self {
        let ty = cells
            .iter()
            .fold(ColType::Unknown, |acc, v| acc.unify(v.col_type()));
        Column {
            name: name.into(),
            ty,
            cells,
        }
    }

    /// The finite numeric projection of this column (nulls and non-numeric
    /// cells dropped). Empty for non-numeric columns — honest absence, not zeros.
    pub fn numeric(&self) -> Vec<f64> {
        self.cells
            .iter()
            .filter_map(Value::as_f64)
            .filter(|x| x.is_finite())
            .collect()
    }

    /// Count of null cells.
    pub fn null_count(&self) -> usize {
        self.cells.iter().filter(|v| v.is_null()).count()
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

/// A normalized corpus: named columns of equal length, plus provenance about
/// where it came from. This is the universal input to every detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordSet {
    /// Logical source identifier (path, URL, or `"-"` for stdin).
    pub source: String,
    /// The format the normalizer recognized (e.g. `"csv"`, `"ndjson"`).
    pub format: String,
    pub columns: Vec<Column>,
}

impl RecordSet {
    /// Creates a record set, panicking only via debug-assert if columns are
    /// ragged. Construction is the normalizer's responsibility; detectors may
    /// rely on rectangularity.
    pub fn new(source: impl Into<String>, format: impl Into<String>, columns: Vec<Column>) -> Self {
        debug_assert!(
            columns.windows(2).all(|w| w[0].len() == w[1].len()),
            "RecordSet columns must be equal length"
        );
        RecordSet {
            source: source.into(),
            format: format.into(),
            columns,
        }
    }

    /// Number of rows (length of the first column, or 0 if columnless).
    pub fn rows(&self) -> usize {
        self.columns.first().map_or(0, Column::len)
    }

    pub fn width(&self) -> usize {
        self.columns.len()
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    /// A copy keeping only the columns named in `names`, in their original
    /// column order (not the order given). Names with no matching column are
    /// silently skipped — callers that must reject an unknown name should
    /// validate with [`Self::column`] first. Provenance is preserved.
    ///
    /// This is the column-scoping primitive behind `scan --columns`: it lets a
    /// caller focus detection on a handful of meaningful columns in a wide
    /// corpus (e.g. journald's dozens of identifier/counter fields).
    pub fn select(&self, names: &[String]) -> RecordSet {
        let keep: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        self.retain(|name| keep.contains(name))
    }

    /// A copy dropping the columns named in `names`, preserving the order and
    /// provenance of the rest. The complement of [`Self::select`], behind
    /// `scan --exclude`.
    pub fn without(&self, names: &[String]) -> RecordSet {
        let drop: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        self.retain(|name| !drop.contains(name))
    }

    /// Shared projection: a copy keeping columns whose name satisfies `keep`.
    fn retain(&self, keep: impl Fn(&str) -> bool) -> RecordSet {
        RecordSet {
            source: self.source.clone(),
            format: self.format.clone(),
            columns: self
                .columns
                .iter()
                .filter(|c| keep(&c.name))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_skips_nulls_and_strings() {
        let col = Column::new(
            "x",
            vec![
                Value::Int(1),
                Value::Null,
                Value::Str("nope".into()),
                Value::Float(2.5),
            ],
        );
        assert_eq!(col.numeric(), vec![1.0, 2.5]);
        assert_eq!(col.ty, ColType::Mixed);
        assert_eq!(col.null_count(), 1);
    }

    #[test]
    fn null_count_is_exact() {
        assert_eq!(
            Column::new("a", vec![Value::Int(1), Value::Int(2)]).null_count(),
            0
        );
        assert_eq!(
            Column::new("b", vec![Value::Null, Value::Int(1), Value::Null]).null_count(),
            2
        );
    }

    #[test]
    fn empty_and_nonempty_columns() {
        assert!(Column::new("e", vec![]).is_empty());
        assert!(!Column::new("f", vec![Value::Int(1)]).is_empty());
    }

    #[test]
    fn rows_and_width() {
        let rs = RecordSet::new(
            "-",
            "csv",
            vec![
                Column::new("a", vec![Value::Int(1), Value::Int(2)]),
                Column::new("b", vec![Value::Int(3), Value::Int(4)]),
            ],
        );
        assert_eq!(rs.rows(), 2);
        assert_eq!(rs.width(), 2);
        assert!(rs.column("a").is_some());
        assert!(rs.column("z").is_none());
    }

    fn abc() -> RecordSet {
        RecordSet::new(
            "src.csv",
            "csv",
            vec![
                Column::new("a", vec![Value::Int(1)]),
                Column::new("b", vec![Value::Int(2)]),
                Column::new("c", vec![Value::Int(3)]),
            ],
        )
    }

    #[test]
    fn select_keeps_named_columns_in_original_order() {
        // Requested order is "c,a" but the projection preserves the corpus's own
        // column order (a then c); the dropped column (b) is gone; provenance kept.
        let rs = abc().select(&["c".to_string(), "a".to_string()]);
        let names: Vec<&str> = rs.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
        assert_eq!(rs.source, "src.csv");
        assert_eq!(rs.format, "csv");
        assert_eq!(rs.rows(), 1);
    }

    #[test]
    fn select_skips_unknown_names() {
        // An unknown name contributes nothing — only the real "a" survives.
        let rs = abc().select(&["a".to_string(), "nope".to_string()]);
        let names: Vec<&str> = rs.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a"]);
    }

    #[test]
    fn select_empty_yields_no_columns() {
        assert_eq!(abc().select(&[]).width(), 0);
    }

    #[test]
    fn without_drops_named_columns_and_keeps_the_rest() {
        let rs = abc().without(&["b".to_string()]);
        let names: Vec<&str> = rs.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
        assert_eq!(rs.source, "src.csv");
        assert_eq!(rs.format, "csv");
    }

    #[test]
    fn without_empty_keeps_everything() {
        assert_eq!(abc().without(&[]).width(), 3);
    }

    #[test]
    fn without_unknown_name_is_a_noop() {
        assert_eq!(abc().without(&["zzz".to_string()]).width(), 3);
    }
}
