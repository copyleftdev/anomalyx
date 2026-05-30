//! Shared row-oriented table builder for the JSON-family parsers.
//!
//! Accumulates record-shaped JSON values into columns with a stable, sorted
//! key-union order. Keys missing from a given record fill with
//! [`ax_core::Value::Null`], so every column ends equal length — absence is
//! explicit, never a guess.

use crate::infer;
use ax_core::{Column, Value};
use std::collections::BTreeMap;

/// Synthetic column name for non-object records (scalars, arrays).
pub const VALUE_COL: &str = "value";

#[derive(Default)]
pub struct TableBuilder {
    order: Vec<String>,
    index: BTreeMap<String, usize>,
    cols: Vec<Vec<Value>>,
    rows: usize,
}

impl TableBuilder {
    pub fn new() -> Self {
        TableBuilder::default()
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
    /// the synthetic [`VALUE_COL`] column.
    pub fn push_value(&mut self, val: serde_json::Value) {
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

    pub fn finish(self) -> Vec<Column> {
        self.order
            .into_iter()
            .zip(self.cols)
            .map(|(name, cells)| Column::new(name, cells))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_union_pads_missing_with_null() {
        let mut b = TableBuilder::new();
        b.push_value(serde_json::json!({"a": 1}));
        b.push_value(serde_json::json!({"a": 2, "b": 9}));
        let cols = b.finish();
        assert_eq!(cols.len(), 2);
        let bcol = cols.iter().find(|c| c.name == "b").unwrap();
        assert_eq!(bcol.null_count(), 1); // first row had no `b`
    }

    #[test]
    fn non_object_goes_to_value_column() {
        let mut b = TableBuilder::new();
        b.push_value(serde_json::json!(7));
        b.push_value(serde_json::json!(8));
        let cols = b.finish();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0].name, VALUE_COL);
        assert_eq!(cols[0].numeric(), vec![7.0, 8.0]);
    }
}
