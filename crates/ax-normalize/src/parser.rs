//! The format-parser plugin contract.
//!
//! Each file format is an independent [`FormatParser`] (one per file under
//! `parsers/`). A [`ParserRegistry`] resolves a byte stream to a parser — by
//! file extension first, then by content sniff — and asks it to produce
//! columns. Adding a format is: write a `parsers/<fmt>.rs`, implement the trait,
//! and register it in [`parsers::default_registry`]. No central `match` to edit.
//!
//! This mirrors the `Detector`/`Registry` pattern in `ax-detect`: explicit
//! registration (so formats are feature-gateable and the set is deterministic),
//! not runtime dynamic loading.

use ax_core::{AxError, Column, RecordSet};

/// Content-sniff confidence. Higher wins; ties break by registration order, so
/// resolution is deterministic. Use the named constants rather than bare ints.
pub type Confidence = u16;

/// A binary magic number matched (e.g. Parquet `PAR1`). Unambiguous.
pub const MAGIC: Confidence = 100;
/// A distinctive text shape that should win over the generic fallback
/// (e.g. NDJSON's repeated object-per-line).
pub const STRONG: Confidence = 60;
/// A recognizable text shape (single JSON document, tab-delimited).
pub const TEXT: Confidence = 50;
/// Last-resort claim — CSV treats any leftover text as comma-delimited.
pub const FALLBACK: Confidence = 1;

/// One file format. Implementors live in `parsers/` — one per format.
pub trait FormatParser: Send + Sync {
    /// Stable identifier, recorded in the envelope's `format` field (e.g. `"csv"`).
    fn id(&self) -> &'static str;

    /// File extensions this parser claims (lower-case, no dot).
    fn extensions(&self) -> &'static [&'static str];

    /// How strongly `bytes` looks like this format, or `None` if it clearly is
    /// not. Used only when the extension doesn't decide.
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence>;

    /// Parse `bytes` (from logical `source`) into columns.
    fn parse(&self, source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError>;
}

/// An ordered set of format parsers.
pub struct ParserRegistry {
    parsers: Vec<Box<dyn FormatParser>>,
}

/// How [`ParserRegistry::resolve_detail`] selected a parser.
enum Resolution {
    /// Matched a declared file extension (the user named the format).
    Extension,
    /// Matched a content sniff at this confidence.
    Sniff(Confidence),
}

impl ParserRegistry {
    pub fn new() -> Self {
        ParserRegistry {
            parsers: Vec::new(),
        }
    }

    pub fn register(&mut self, parser: Box<dyn FormatParser>) -> &mut Self {
        self.parsers.push(parser);
        self
    }

    /// Registered parser ids, in order (handy for `describe`/tests).
    pub fn ids(&self) -> Vec<&'static str> {
        self.parsers.iter().map(|p| p.id()).collect()
    }

    /// The lower-cased final extension of `source`, if any.
    fn extension(source: &str) -> Option<String> {
        source.rsplit('.').next().map(|e| e.to_ascii_lowercase())
    }

    /// How a parser was chosen — used to decide whether a downstream parse
    /// failure is a real "malformed file" error or just a wrong content guess.
    fn resolve_detail(
        &self,
        source: &str,
        bytes: &[u8],
    ) -> Result<(&dyn FormatParser, Resolution), AxError> {
        if let Some(ext) = Self::extension(source) {
            if let Some(p) = self
                .parsers
                .iter()
                .find(|p| p.extensions().contains(&ext.as_str()))
            {
                return Ok((p.as_ref(), Resolution::Extension));
            }
        }
        // Highest sniff confidence; strict `>` keeps the first registered winner.
        let mut best: Option<(Confidence, &dyn FormatParser)> = None;
        for p in &self.parsers {
            if let Some(c) = p.sniff(bytes) {
                if best.is_none_or(|(bc, _)| c > bc) {
                    best = Some((c, p.as_ref()));
                }
            }
        }
        best.map(|(c, p)| (p, Resolution::Sniff(c)))
            .ok_or_else(|| AxError::UnknownFormat(source.to_string()))
    }

    /// Resolves the parser for `source`/`bytes`: a matching file extension wins;
    /// otherwise the highest-confidence content sniff (first registered on a
    /// tie). An unrecognized stream is [`AxError::UnknownFormat`], never a guess.
    pub fn resolve(&self, source: &str, bytes: &[u8]) -> Result<&dyn FormatParser, AxError> {
        self.resolve_detail(source, bytes).map(|(p, _)| p)
    }

    /// Resolve, parse, and wrap into a [`RecordSet`] tagged with the parser id.
    ///
    /// When the parser was picked by a *weak* (`TEXT`/`FALLBACK`) content sniff
    /// and then fails to parse, the content guess was simply wrong — so the
    /// stream is reported as [`AxError::UnknownFormat`], not with that parser's
    /// internal error (e.g. a plain-text file that merely starts with `[` is
    /// "unrecognized", not "invalid JSON"). An explicit extension or a
    /// `MAGIC`/`STRONG` signature that then fails is a genuine malformed-file
    /// error and is surfaced as-is.
    pub fn normalize(&self, source: &str, bytes: &[u8]) -> Result<RecordSet, AxError> {
        let (parser, how) = self.resolve_detail(source, bytes)?;
        match parser.parse(source, bytes) {
            Ok(columns) => Ok(RecordSet::new(source, parser.id(), columns)),
            Err(_) if matches!(how, Resolution::Sniff(c) if c < STRONG) => {
                Err(AxError::UnknownFormat(source.to_string()))
            }
            Err(e) => Err(e),
        }
    }

    /// Normalize with an explicitly chosen parser id (skips detection).
    pub fn normalize_with(
        &self,
        id: &str,
        source: &str,
        bytes: &[u8],
    ) -> Result<RecordSet, AxError> {
        let parser = self
            .parsers
            .iter()
            .find(|p| p.id() == id)
            .ok_or_else(|| AxError::Config(format!("unknown format id '{id}'")))?;
        Ok(RecordSet::new(
            source,
            parser.id(),
            parser.parse(source, bytes)?,
        ))
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        crate::parsers::default_registry()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> ParserRegistry {
        ParserRegistry::default()
    }

    #[test]
    fn extension_wins_over_content() {
        // .csv extension is honored even though the bytes look like JSON.
        let r = reg();
        let p = r.resolve("data.csv", b"{\"a\":1}").unwrap();
        assert_eq!(p.id(), "csv");
    }

    #[test]
    fn sniff_used_without_a_known_extension() {
        assert_eq!(reg().resolve("-", b"a,b\n1,2").unwrap().id(), "csv");
        assert_eq!(reg().resolve("-", b"a\tb\n1\t2").unwrap().id(), "tsv");
        assert_eq!(reg().resolve("-", b"[{\"a\":1}]").unwrap().id(), "json");
        assert_eq!(
            reg().resolve("-", b"{\"a\":1}\n{\"a\":2}\n").unwrap().id(),
            "ndjson"
        );
    }

    #[cfg(feature = "polars")]
    #[test]
    fn binary_magic_outranks_text_sniff() {
        assert_eq!(
            reg().resolve("-", b"PAR1\x00\x01x").unwrap().id(),
            "parquet"
        );
        assert_eq!(
            reg().resolve("-", b"ARROW1\x00\x00x").unwrap().id(),
            "arrow"
        );
    }

    #[test]
    fn csv_mentioning_par1_is_still_csv() {
        // a CSV that merely mentions PAR1 in its data is not Parquet
        assert_eq!(reg().resolve("-", b"a,b\nPAR1,2").unwrap().id(), "csv");
    }

    #[test]
    fn unrecognized_stream_errors() {
        assert!(matches!(
            reg().resolve("-", &[0x00, 0x01, 0x02, 0xff]),
            Err(AxError::UnknownFormat(_))
        ));
    }

    #[test]
    fn weak_sniff_parse_failure_is_unrecognized_not_misleading() {
        // A plain-text line that merely starts with `[` (e.g. an Apache
        // error_log) is grabbed by the JSON parser's cheap TEXT sniff. When the
        // JSON parse then fails, the content guess was wrong → report
        // UnknownFormat, not a confusing "invalid JSON" parse error.
        let r = reg().normalize("-", b"[Sun Dec 04 04:47:44 2005] [error] not json");
        assert!(matches!(r, Err(AxError::UnknownFormat(_))), "got {r:?}");
    }

    #[test]
    fn malformed_input_under_a_claimed_extension_is_a_parse_error() {
        // But when the FORMAT was confidently identified — here by the `.json`
        // extension — a parse failure is a genuine malformed-file error and is
        // surfaced as such, not masked as UnknownFormat.
        let r = reg().normalize("data.json", b"{not valid json");
        assert!(matches!(r, Err(AxError::Parse { .. })), "got {r:?}");
    }

    #[test]
    fn malformed_input_under_a_strong_sniff_is_a_parse_error() {
        // A STRONG content signature that then fails to parse is a real
        // malformed-file error, not "unrecognized" — pins the `< STRONG`
        // boundary. Zeek sniffs STRONG on `#separator` but needs `#fields`.
        let r = reg().normalize("-", b"#separator \\x09\n#path\tconn\n");
        assert!(matches!(r, Err(AxError::Parse { .. })), "got {r:?}");
    }

    #[test]
    fn extension_overrides_content_sniff() {
        // The file extension forces a parser even when the bytes would sniff as
        // something else — which pins each parser's `extensions()`.
        let r = reg();
        assert_eq!(r.resolve("x.tsv", b"a,b\n1,2").unwrap().id(), "tsv");
        assert_eq!(r.resolve("x.tab", b"a,b\n1,2").unwrap().id(), "tsv");
        assert_eq!(r.resolve("x.json", b"a,b").unwrap().id(), "json");
        assert_eq!(r.resolve("x.jsonl", b"a,b").unwrap().id(), "ndjson");
        assert_eq!(r.resolve("x.csv", b"a\tb").unwrap().id(), "csv");
    }

    #[cfg(feature = "polars")]
    #[test]
    fn binary_extensions_resolve() {
        let r = reg();
        assert_eq!(r.resolve("x.parquet", b"zz").unwrap().id(), "parquet");
        assert_eq!(r.resolve("x.pq", b"zz").unwrap().id(), "parquet");
        assert_eq!(r.resolve("x.feather", b"zz").unwrap().id(), "arrow");
        assert_eq!(r.resolve("x.ipc", b"zz").unwrap().id(), "arrow");
    }

    #[test]
    fn default_registry_lists_all_formats() {
        // Registration order is the deterministic tie-break. Binary readers are
        // feature-gated, so the expected list is composed per active feature.
        let mut expected: Vec<&str> = Vec::new();
        #[cfg(feature = "polars")]
        {
            expected.push("parquet");
            expected.push("arrow");
        }
        #[cfg(feature = "evtx")]
        expected.push("evtx");
        #[cfg(feature = "pcap")]
        expected.push("pcap");
        #[cfg(feature = "xlsx")]
        expected.push("xlsx");
        #[cfg(feature = "sqlite")]
        expected.push("sqlite");
        #[cfg(feature = "datalake")]
        {
            expected.push("avro");
            expected.push("orc");
        }
        expected.extend([
            "otlp",
            "cloudtrail",
            "eve",
            "journal",
            "osquery",
            "ndjson",
            "zeek",
            "logfmt",
            "accesslog",
            "syslog",
            "cef",
            "leef",
            "auditd",
            "dns",
            "prometheus",
            "xml",
            "json",
            "yaml",
            "toml",
            "ini",
            "netflow",
            "vpcflow",
            "tsv",
            "csv",
        ]);
        assert_eq!(reg().ids(), expected);
    }
}
