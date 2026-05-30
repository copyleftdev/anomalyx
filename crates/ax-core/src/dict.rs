//! A deterministic string interner backing the envelope's dictionary table.
//!
//! The article calls for "dictionary-pinned string tables (no magic
//! constants)": every repeated string in the output appears once in a `dict`
//! array and is referenced elsewhere by index. Interning here is insertion-
//! ordered, so the table — and every index into it — is stable for a given
//! sequence of `intern` calls. Identical inputs produce an identical table.

use serde::Serialize;
use std::collections::HashMap;

/// Insertion-ordered string interner. `intern` is idempotent: the same string
/// always returns the same index.
#[derive(Debug, Default, Clone)]
pub struct Dict {
    table: Vec<String>,
    index: HashMap<String, u32>,
}

impl Dict {
    pub fn new() -> Self {
        Dict::default()
    }

    /// Returns the index for `s`, assigning the next index on first sight.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.index.get(s) {
            return i;
        }
        let i = self.table.len() as u32;
        self.table.push(s.to_string());
        self.index.insert(s.to_string(), i);
        i
    }

    /// Resolves an index back to its string, if present.
    pub fn get(&self, i: u32) -> Option<&str> {
        self.table.get(i as usize).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// The backing table, for serialization into the envelope's `dict` field.
    pub fn as_slice(&self) -> &[String] {
        &self.table
    }
}

impl Serialize for Dict {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.table.serialize(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_is_idempotent_and_ordered() {
        let mut d = Dict::new();
        assert_eq!(d.intern("a"), 0);
        assert_eq!(d.intern("b"), 1);
        assert_eq!(d.intern("a"), 0);
        assert_eq!(d.len(), 2);
        assert_eq!(d.get(1), Some("b"));
        assert_eq!(d.get(9), None);
    }

    #[test]
    fn is_empty_and_as_slice_track_contents() {
        let mut d = Dict::new();
        assert!(d.is_empty());
        d.intern("a");
        d.intern("b");
        assert!(!d.is_empty());
        assert_eq!(d.as_slice(), &["a".to_string(), "b".to_string()]);
    }
}
