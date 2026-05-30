//! Format identification: by extension when we have a path, by content sniff
//! for stdin. Detection is conservative — an unrecognized stream is an
//! [`AxError::UnknownFormat`], never a silent guess.

use ax_core::AxError;

/// The input formats the text normalizer understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Tsv,
    /// Newline-delimited JSON (one JSON value per line).
    Ndjson,
    /// A single JSON document (array of objects, object, or array of scalars).
    Json,
    /// Apache Parquet (binary columnar). Requires the `polars` feature to read.
    Parquet,
    /// Apache Arrow IPC / Feather file (binary columnar). Requires `polars`.
    Arrow,
}

impl Format {
    /// Stable token recorded in the envelope's `format` field.
    pub fn token(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Tsv => "tsv",
            Format::Ndjson => "ndjson",
            Format::Json => "json",
            Format::Parquet => "parquet",
            Format::Arrow => "arrow",
        }
    }

    /// Whether this format is binary columnar (read via the Polars backbone).
    pub fn is_binary(self) -> bool {
        matches!(self, Format::Parquet | Format::Arrow)
    }

    /// Picks a format from a file extension, if recognized.
    pub fn from_extension(path: &str) -> Option<Format> {
        let ext = path.rsplit('.').next()?.to_ascii_lowercase();
        match ext.as_str() {
            "csv" => Some(Format::Csv),
            "tsv" | "tab" => Some(Format::Tsv),
            "ndjson" | "jsonl" => Some(Format::Ndjson),
            "json" => Some(Format::Json),
            "parquet" | "pq" => Some(Format::Parquet),
            "arrow" | "ipc" | "feather" => Some(Format::Arrow),
            _ => None,
        }
    }

    /// Sniffs a format from leading content. Binary magic numbers are checked
    /// first (they are not valid UTF-8); then textual sniffing. `None` if
    /// nothing matches.
    pub fn sniff(bytes: &[u8]) -> Option<Format> {
        // Parquet files begin (and end) with the 4-byte magic "PAR1".
        if bytes.starts_with(b"PAR1") {
            return Some(Format::Parquet);
        }
        // Arrow IPC files begin with "ARROW1".
        if bytes.starts_with(b"ARROW1") {
            return Some(Format::Arrow);
        }
        let text = std::str::from_utf8(bytes).ok()?;
        let trimmed = text.trim_start();
        let first = trimmed.chars().next()?;
        match first {
            '[' => Some(Format::Json),
            '{' => {
                // One object → json; multiple object-lines → ndjson.
                let object_lines = trimmed
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .take(3)
                    .filter(|l| l.trim_start().starts_with('{'))
                    .count();
                if object_lines >= 2 {
                    Some(Format::Ndjson)
                } else {
                    Some(Format::Json)
                }
            }
            _ => {
                // Tabular: prefer TSV if a tab appears before any comma on line 1.
                let line = trimmed.lines().next()?;
                // Indices of '\t' and ',' are positions of distinct characters,
                // so they are never equal; `<` is the only meaningful test.
                match (line.find('\t'), line.find(',')) {
                    (Some(t), Some(c)) if t < c => Some(Format::Tsv),
                    (Some(_), None) => Some(Format::Tsv),
                    _ => Some(Format::Csv), // comma-first, or single comma-free column
                }
            }
        }
    }

    /// Resolves the format for `source`/`bytes`: extension first, then sniff.
    pub fn resolve(source: &str, bytes: &[u8]) -> Result<Format, AxError> {
        if let Some(f) = Format::from_extension(source) {
            return Ok(f);
        }
        Format::sniff(bytes).ok_or_else(|| AxError::UnknownFormat(source.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tokens_are_exact() {
        assert_eq!(Format::Csv.token(), "csv");
        assert_eq!(Format::Tsv.token(), "tsv");
        assert_eq!(Format::Ndjson.token(), "ndjson");
        assert_eq!(Format::Json.token(), "json");
        assert_eq!(Format::Parquet.token(), "parquet");
        assert_eq!(Format::Arrow.token(), "arrow");
    }

    #[test]
    fn binary_classification() {
        assert!(Format::Parquet.is_binary());
        assert!(Format::Arrow.is_binary());
        assert!(!Format::Csv.is_binary());
        assert!(!Format::Json.is_binary());
    }

    #[test]
    fn binary_extensions_and_magic() {
        assert_eq!(Format::from_extension("x.parquet"), Some(Format::Parquet));
        assert_eq!(Format::from_extension("x.feather"), Some(Format::Arrow));
        assert_eq!(Format::from_extension("x.ipc"), Some(Format::Arrow));
        // magic numbers win for extensionless input
        assert_eq!(Format::sniff(b"PAR1\x00\x01rest"), Some(Format::Parquet));
        assert_eq!(Format::sniff(b"ARROW1\x00\x00rest"), Some(Format::Arrow));
        // a CSV that merely mentions PAR1 later is still CSV
        assert_eq!(Format::sniff(b"a,b\nPAR1,2"), Some(Format::Csv));
    }

    #[test]
    fn extension_detection() {
        assert_eq!(Format::from_extension("a/b.csv"), Some(Format::Csv));
        assert_eq!(Format::from_extension("x.tsv"), Some(Format::Tsv));
        assert_eq!(Format::from_extension("x.tab"), Some(Format::Tsv));
        assert_eq!(Format::from_extension("x.json"), Some(Format::Json));
        assert_eq!(Format::from_extension("x.JSONL"), Some(Format::Ndjson));
        assert_eq!(Format::from_extension("x.xlsx"), None);
        assert_eq!(Format::from_extension("noext"), None);
    }

    #[test]
    fn sniff_uses_delimiter_order_when_both_present() {
        // tab before comma → TSV; comma before tab → CSV.
        assert_eq!(Format::sniff(b"a\tb,c\n1\t2,3"), Some(Format::Tsv));
        assert_eq!(Format::sniff(b"a,b\tc\n1,2\t3"), Some(Format::Csv));
    }

    #[test]
    fn sniff_json_vs_ndjson() {
        assert_eq!(Format::sniff(b"[{\"a\":1}]"), Some(Format::Json));
        assert_eq!(
            Format::sniff(b"{\"a\":1}\n{\"a\":2}\n"),
            Some(Format::Ndjson)
        );
        assert_eq!(Format::sniff(b"{\"a\":1}"), Some(Format::Json));
    }

    #[test]
    fn sniff_csv_vs_tsv() {
        assert_eq!(Format::sniff(b"a,b,c\n1,2,3"), Some(Format::Csv));
        assert_eq!(Format::sniff(b"a\tb\tc\n1\t2\t3"), Some(Format::Tsv));
    }

    #[test]
    fn resolve_prefers_extension_then_sniff() {
        // extension wins even if content looks like something else
        assert_eq!(
            Format::resolve("data.csv", b"{\"a\":1}").unwrap(),
            Format::Csv
        );
        // no extension → sniff
        assert_eq!(Format::resolve("-", b"a,b\n1,2").unwrap(), Format::Csv);
        assert!(Format::resolve("-", &[0xff, 0xfe, 0x00]).is_err());
    }
}
