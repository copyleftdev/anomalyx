//! Prometheus / OpenMetrics text exposition parser — scrape dumps.
//!
//! Each sample line is `name{label="v",...} value [timestamp]`. We pivot the
//! exposition into a row-per-sample table where **the metric name is its own
//! value column** (so a per-series `point` spike is visible), every label key is
//! its own `Str` column, and the optional millisecond `timestamp` is one more
//! column. A sample that omits a given metric/label leaves that cell `Null`
//! (honest absence). Non-finite values (`+Inf`, `-Inf`, `NaN`) become `Null` —
//! they cannot enter a deterministic numeric reduction.
//!
//! `# HELP` / `# TYPE` / `# UNIT` / `# EOF` and plain `#` comments are metadata
//! and produce no rows. Detected by the exposition shape; claims the `.prom`
//! extension (the node_exporter textfile convention).

use crate::parser::{Confidence, FormatParser, STRONG};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone)]
pub struct PrometheusParser;

/// A metric/label name may start with a letter, `_`, or `:`; subsequent
/// characters may also be digits. (Leniently shared by metric and label names —
/// real label names never use `:`, so accepting it is harmless.)
fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == ':'
}
fn is_name_char(c: char) -> bool {
    is_name_start(c) || c.is_ascii_digit()
}

/// A parsed sample line.
#[derive(Debug)]
struct Sample {
    name: String,
    labels: Vec<(String, String)>,
    value: Value,
    timestamp: Option<i64>,
}

/// A character cursor over one line.
struct Cursor<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.pos += 1;
        }
    }
    /// Reads a `name`-shaped identifier; `None` if the next char can't start one.
    fn read_name(&mut self) -> Option<String> {
        match self.peek() {
            Some(c) if is_name_start(c) => {}
            _ => return None,
        }
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if is_name_char(c) {
                s.push(c);
                self.bump();
            } else {
                break;
            }
        }
        Some(s)
    }
    /// Reads a run of non-whitespace characters (value / timestamp token).
    fn read_token(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' {
                break;
            }
            s.push(c);
            self.bump();
        }
        s
    }
}

/// Parses a `{...}` label set; the cursor is positioned just after `{`.
fn read_labels(cur: &mut Cursor) -> Result<Vec<(String, String)>, String> {
    let mut labels = Vec::new();
    loop {
        cur.skip_ws();
        match cur.peek() {
            Some('}') => {
                cur.bump();
                return Ok(labels);
            }
            None => return Err("unterminated label set".into()),
            _ => {}
        }
        let name = cur.read_name().ok_or("expected label name")?;
        cur.skip_ws();
        if cur.bump() != Some('=') {
            return Err("expected '=' after label name".into());
        }
        cur.skip_ws();
        if cur.bump() != Some('"') {
            return Err("expected '\"' to open label value".into());
        }
        labels.push((name, read_label_value(cur)?));
        cur.skip_ws();
        match cur.bump() {
            Some(',') => continue,
            Some('}') => return Ok(labels),
            _ => return Err("expected ',' or '}' after label".into()),
        }
    }
}

/// Reads a quoted label value (cursor just after the opening `"`), decoding the
/// three Prometheus escapes `\\`, `\"`, `\n`.
fn read_label_value(cur: &mut Cursor) -> Result<String, String> {
    let mut s = String::new();
    loop {
        match cur.bump() {
            None => return Err("unterminated label value".into()),
            Some('"') => return Ok(s),
            Some('\\') => match cur.bump() {
                Some('\\') => s.push('\\'),
                Some('"') => s.push('"'),
                Some('n') => s.push('\n'),
                Some(other) => s.push(other),
                None => return Err("dangling escape in label value".into()),
            },
            Some(c) => s.push(c),
        }
    }
}

/// A metric value is a float64; non-finite (`+Inf`/`-Inf`/`NaN`) maps to `Null`.
fn parse_value(tok: &str) -> Result<Value, String> {
    match tok.parse::<f64>() {
        Ok(f) if f.is_finite() => Ok(Value::Float(f)),
        Ok(_) => Ok(Value::Null),
        Err(_) => Err(format!("invalid metric value '{tok}'")),
    }
}

/// Parses one non-comment sample line.
fn parse_sample(line: &str) -> Result<Sample, String> {
    let chars: Vec<char> = line.chars().collect();
    let mut cur = Cursor {
        chars: &chars,
        pos: 0,
    };
    cur.skip_ws();
    let name = cur.read_name().ok_or("expected metric name")?;
    let labels = if cur.peek() == Some('{') {
        cur.bump();
        read_labels(&mut cur)?
    } else {
        Vec::new()
    };
    cur.skip_ws();
    let value_tok = cur.read_token();
    if value_tok.is_empty() {
        return Err("missing metric value".into());
    }
    let value = parse_value(&value_tok)?;
    cur.skip_ws();
    // An optional timestamp, unless an OpenMetrics exemplar (`# ...`) follows.
    let timestamp = match cur.peek() {
        None | Some('#') => None,
        Some(_) => {
            let ts = cur.read_token();
            Some(
                ts.parse::<i64>()
                    .map_err(|_| format!("invalid timestamp '{ts}'"))?,
            )
        }
    };
    Ok(Sample {
        name,
        labels,
        value,
        timestamp,
    })
}

/// Is this a `#`-comment line (metadata, never a sample)?
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

impl PrometheusParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for PrometheusParser {
    fn id(&self) -> &'static str {
        "prometheus"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["prom"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        let text = std::str::from_utf8(bytes).ok()?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if is_comment(line) {
                // A HELP/TYPE/UNIT/EOF directive is a decisive signal; a plain
                // comment is inconclusive, so keep scanning.
                let rest = line.trim_start().trim_start_matches('#').trim_start();
                if rest.starts_with("HELP ")
                    || rest.starts_with("TYPE ")
                    || rest.starts_with("UNIT ")
                    || rest == "EOF"
                {
                    return Some(STRONG);
                }
                continue;
            }
            // The first real (non-comment) line decides: a parseable sample is
            // the exposition format; anything else clearly is not.
            return parse_sample(line).ok().map(|_| STRONG);
        }
        None
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        let text = std::str::from_utf8(bytes).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        for line in text.lines() {
            if line.trim().is_empty() || is_comment(line) {
                continue;
            }
            let sample = parse_sample(line).map_err(|m| self.err(m))?;
            let mut row: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in sample.labels {
                row.insert(k, Value::Str(v));
            }
            if let Some(ts) = sample.timestamp {
                row.insert("timestamp".into(), Value::Int(ts));
            }
            // The metric name is its own value column; inserted last so it wins
            // any (pathological) collision with a label named the same.
            row.insert(sample.name, sample.value);
            builder.push_row(row);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    const SCRAPE: &str = "\
# HELP http_requests_total The total number of HTTP requests.\n\
# TYPE http_requests_total counter\n\
http_requests_total{method=\"post\",code=\"200\"} 1027 1395066363000\n\
http_requests_total{method=\"post\",code=\"400\"} 3 1395066363000\n\
# a plain comment\n\
metric_without_labels 12.47\n\
go_gc_duration_seconds{quantile=\"0.5\"} 0.0001\n\
# EOF\n";

    fn parse(s: &str) -> Vec<Column> {
        PrometheusParser.parse("-", s.as_bytes()).unwrap()
    }
    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn pivots_metric_name_into_value_column() {
        let cols = parse(SCRAPE);
        let reqs = col(&cols, "http_requests_total");
        assert_eq!(reqs.ty, ColType::Float);
        assert_eq!(reqs.cells.len(), 4, "one row per sample line");
        assert_eq!(reqs.cells[0], Value::Float(1027.0));
        assert_eq!(reqs.cells[1], Value::Float(3.0));
        // Rows from other metrics leave this column null — per-series isolation.
        assert_eq!(reqs.cells[2], Value::Null);
        assert_eq!(reqs.cells[3], Value::Null);
        assert_eq!(
            col(&cols, "metric_without_labels").cells[2],
            Value::Float(12.47)
        );
        assert_eq!(
            col(&cols, "go_gc_duration_seconds").cells[3],
            Value::Float(0.0001)
        );
    }

    #[test]
    fn labels_become_string_columns() {
        let cols = parse(SCRAPE);
        let method = col(&cols, "method");
        assert_eq!(method.ty, ColType::Str);
        assert_eq!(method.cells[0], Value::Str("post".into()));
        assert_eq!(method.cells[2], Value::Null, "unlabeled sample → null");
        assert_eq!(col(&cols, "code").cells[1], Value::Str("400".into()));
        assert_eq!(col(&cols, "quantile").cells[3], Value::Str("0.5".into()));
    }

    #[test]
    fn timestamp_is_an_int_column_padded_with_null() {
        let cols = parse(SCRAPE);
        let ts = col(&cols, "timestamp");
        assert_eq!(ts.ty, ColType::Int);
        assert_eq!(ts.cells[0], Value::Int(1_395_066_363_000));
        assert_eq!(ts.cells[2], Value::Null, "no timestamp on that sample");
    }

    #[test]
    fn label_value_escapes_decode() {
        let cols = parse("m{path=\"C:\\\\DirA\",err=\"a\\\"b\\nc\"} 1\n");
        assert_eq!(col(&cols, "path").cells[0], Value::Str("C:\\DirA".into()));
        assert_eq!(col(&cols, "err").cells[0], Value::Str("a\"b\nc".into()));
        assert_eq!(col(&cols, "m").cells[0], Value::Float(1.0));
    }

    #[test]
    fn non_finite_values_are_null() {
        let cols = parse("a +Inf\nb -Inf\nc NaN\n");
        assert_eq!(col(&cols, "a").cells[0], Value::Null);
        assert_eq!(col(&cols, "b").cells[1], Value::Null);
        assert_eq!(col(&cols, "c").cells[2], Value::Null);
    }

    #[test]
    fn names_allow_colon_underscore_and_digits() {
        // Colon start, underscore, and a trailing digit all in one name.
        let cols = parse(":_m1 5\n");
        assert_eq!(col(&cols, ":_m1").cells[0], Value::Float(5.0));
        // A label name with underscore start and a digit.
        let c2 = parse("x{_l1=\"v\"} 1\n");
        assert_eq!(col(&c2, "_l1").cells[0], Value::Str("v".into()));
    }

    #[test]
    fn trailing_comma_in_labels_is_accepted() {
        let cols = parse("m{a=\"1\",} 2\n");
        assert_eq!(col(&cols, "a").cells[0], Value::Str("1".into()));
        assert_eq!(col(&cols, "m").cells[0], Value::Float(2.0));
    }

    #[test]
    fn malformed_lines_error() {
        // digit-leading name
        assert!(PrometheusParser.parse("-", b"1bad 5\n").is_err());
        // missing value
        assert!(PrometheusParser
            .parse("-", b"http_requests_total\n")
            .is_err());
        // non-numeric value
        assert!(PrometheusParser.parse("-", b"foo abc\n").is_err());
        // unquoted label value
        assert!(PrometheusParser.parse("-", b"foo{a=1} 5\n").is_err());
        // non-integer timestamp
        assert!(PrometheusParser.parse("-", b"foo 1 1.5\n").is_err());
        // unterminated label set
        assert!(PrometheusParser.parse("-", b"foo{a=\"1\" 5\n").is_err());
    }

    #[test]
    fn sniff_recognizes_exposition() {
        assert_eq!(PrometheusParser.sniff(SCRAPE.as_bytes()), Some(STRONG));
        // A bare sample line (no HELP/TYPE) still sniffs.
        assert_eq!(
            PrometheusParser.sniff(b"node_cpu_seconds_total 42.5\n"),
            Some(STRONG)
        );
        // Each HELP/TYPE/UNIT/EOF directive alone is decisive.
        assert_eq!(PrometheusParser.sniff(b"# HELP foo bar\n"), Some(STRONG));
        assert_eq!(
            PrometheusParser.sniff(b"# TYPE foo counter\n"),
            Some(STRONG)
        );
        assert_eq!(PrometheusParser.sniff(b"# UNIT foo bytes\n"), Some(STRONG));
        assert_eq!(PrometheusParser.sniff(b"# EOF\n"), Some(STRONG));
        // A plain comment is inconclusive on its own.
        assert_eq!(PrometheusParser.sniff(b"# just a note\n"), None);
        // Other formats are rejected.
        assert_eq!(PrometheusParser.sniff(b"a,b,c\n1,2,3"), None); // CSV
        assert_eq!(PrometheusParser.sniff(b"k=1 v=2\n"), None); // logfmt
        assert_eq!(PrometheusParser.sniff(b"{\"a\":1}\n"), None); // JSON
    }

    #[test]
    fn comment_then_sample_sniffs_via_the_sample() {
        assert_eq!(
            PrometheusParser.sniff(b"# a note\nfoo_total 3\n"),
            Some(STRONG)
        );
        assert_eq!(PrometheusParser.sniff(b"# a note\nnonsense !!!\n"), None);
    }

    #[test]
    fn unterminated_label_set_has_its_own_diagnostic() {
        // Running off the end at the top of the label loop (vs. a bad token
        // mid-pair) is a distinct error — pins the dedicated `None` arm.
        assert_eq!(parse_sample("m{").unwrap_err(), "unterminated label set");
        assert_eq!(
            parse_sample("m{a=\"1\",").unwrap_err(),
            "unterminated label set"
        );
    }

    #[test]
    fn claims_the_prom_extension() {
        assert_eq!(PrometheusParser.extensions(), &["prom"]);
    }

    #[test]
    fn resolves_by_extension_and_content() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(
            reg.resolve("node.prom", b"# HELP x y\n").unwrap().id(),
            "prometheus"
        );
        // Routed by content sniff without a known extension.
        assert_eq!(
            reg.resolve("-", SCRAPE.as_bytes()).unwrap().id(),
            "prometheus"
        );
    }
}
