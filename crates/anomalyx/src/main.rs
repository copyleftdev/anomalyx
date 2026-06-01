//! # anomalyx — the command-line contract
//!
//! Four discoverable verbs, exactly as the article prescribes:
//!
//! ```text
//! anomalyx describe          # protocol metadata: what this is, what it does
//! anomalyx schema            # machine-readable shape of `scan` output
//! anomalyx scan [PATH]       # normalize + detect → dense tq1 envelope
//! anomalyx explain <HANDLE>  # resolve a handle to its underlying evidence
//! ```
//!
//! Output is the dense `tq1` JSON envelope, not pretty text. Exit codes are
//! committed: `0` clean, `1` anomalies found, `2` tool error.

use ax_core::envelope::{EnvelopeBuilder, ExitCode, PROTOCOL};
use ax_core::finding::{Handle, Severity};
use ax_core::{AxError, ColumnRole, RecordSet, Value};
use ax_detect::{DetectConfig, Registry, ScanContext};
use std::io::Read;
use std::process::ExitCode as ProcExit;

mod describe;
mod schema;

fn main() -> ProcExit {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ProcExit::from(code.code() as u8),
        Err(e) => {
            eprintln!("anomalyx: error: {e}");
            ProcExit::from(ExitCode::Error.code() as u8)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, AxError> {
    let Some((cmd, rest)) = args.split_first() else {
        eprintln!("{}", usage());
        return Ok(ExitCode::Error);
    };
    match cmd.as_str() {
        "describe" => {
            println!("{}", describe::describe_json());
            Ok(ExitCode::Clean)
        }
        "schema" => {
            println!("{}", schema::envelope_schema());
            Ok(ExitCode::Clean)
        }
        "scan" => cmd_scan(rest),
        "explain" => cmd_explain(rest),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(ExitCode::Clean)
        }
        "-V" | "--version" | "version" => {
            println!("anomalyx {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::Clean)
        }
        other => Err(AxError::Config(format!(
            "unknown command '{other}'\n{}",
            usage()
        ))),
    }
}

fn usage() -> &'static str {
    "anomalyx — contract-first anomaly detection\n\
     \n\
     USAGE:\n\
     \x20 anomalyx describe                         Protocol metadata\n\
     \x20 anomalyx schema                           JSON Schema of scan output\n\
     \x20 anomalyx scan [--baseline B] [--period N] [--cadence COL] [--columns C,..|--exclude C,..] [PATH]\n\
     \x20 anomalyx explain <HANDLE> [--baseline B] [--period N] [--cadence COL] [--columns C,..|--exclude C,..] [PATH]\n\
     \n\
     --baseline B  compare against B (distributional drift + schema-diff)\n\
     --period N    treat rows as a time series of period N (contextual/seasonal)\n\
     --cadence COL assess column COL for metronomic timing (cadence)\n\
     --cad-max-cv F max inter-arrival CV for the cadence flag (default 0.05)\n\
     --fdr Q       point detector: Benjamini–Hochberg FDR control at level Q\n\
     \x20             (0<Q≤1), replacing the fixed modified-z threshold\n\
     --columns C,.. analyze only these columns (focus a wide corpus)\n\
     --exclude C,.. analyze every column except these\n\
     --top N       emit only the N most severe findings (summary/exit unchanged)\n\
     --min-severity S  emit only findings ≥ S (info|low|medium|high|critical)\n\
     --no-column-roles  don't skip identifier/sequence columns (roles still shown)\n\
     EXIT: 0 clean · 1 anomalies found · 2 error"
}

/// Parsed scan/explain arguments: optional `--baseline <PATH>`, optional
/// `--period <N>`, and the remaining positionals. Fails cleanly on a flag with a
/// missing or malformed value.
#[derive(Debug, Default, PartialEq)]
struct ScanArgs {
    baseline: Option<String>,
    period: Option<usize>,
    cadence: Option<String>,
    /// `--cad-max-cv`: cadence regularity threshold (max inter-arrival CV).
    cad_max_cv: Option<f64>,
    /// `--fdr`: false-discovery-rate level for the point detector (replaces the
    /// fixed modified-z threshold with Benjamini–Hochberg control).
    fdr: Option<f64>,
    /// `--columns`: analyze only these columns (allowlist).
    columns: Option<Vec<String>>,
    /// `--exclude`: analyze every column except these (denylist).
    exclude: Option<Vec<String>>,
    /// `--top`: emit only the N most severe findings (output scoping).
    top: Option<usize>,
    /// `--min-severity`: emit only findings at or above this severity.
    min_severity: Option<Severity>,
    /// `--no-column-roles`: disable role-based detector skipping (roles are
    /// still reported in the envelope).
    no_column_roles: bool,
    positional: Vec<String>,
}

/// Parses a severity name (case-insensitive) to its bucket.
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Splits a `--columns`/`--exclude` value into trimmed, non-empty column names.
fn parse_column_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_scan_args(args: &[String]) -> Result<ScanArgs, AxError> {
    let mut parsed = ScanArgs::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--baseline" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--baseline requires a path".into()))?;
                parsed.baseline = Some(v.clone());
            }
            "--period" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--period requires an integer".into()))?;
                let n = v.parse::<usize>().map_err(|_| {
                    AxError::Config(format!("--period must be an integer, got '{v}'"))
                })?;
                parsed.period = Some(n);
            }
            "--cadence" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--cadence requires a column name".into()))?;
                parsed.cadence = Some(v.clone());
            }
            "--cad-max-cv" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--cad-max-cv requires a number".into()))?;
                let cv = v.parse::<f64>().map_err(|_| {
                    AxError::Config(format!("--cad-max-cv must be a number, got '{v}'"))
                })?;
                if !cv.is_finite() || cv < 0.0 {
                    return Err(AxError::Config(format!(
                        "--cad-max-cv must be a finite, non-negative coefficient of variation, got '{v}'"
                    )));
                }
                parsed.cad_max_cv = Some(cv);
            }
            "--fdr" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--fdr requires a number".into()))?;
                let q = v
                    .parse::<f64>()
                    .map_err(|_| AxError::Config(format!("--fdr must be a number, got '{v}'")))?;
                if !q.is_finite() || q <= 0.0 || q > 1.0 {
                    return Err(AxError::Config(format!(
                        "--fdr must be a false-discovery rate in (0, 1], got '{v}'"
                    )));
                }
                parsed.fdr = Some(q);
            }
            "--top" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--top requires an integer".into()))?;
                let n = v.parse::<usize>().ok().filter(|&n| n >= 1).ok_or_else(|| {
                    AxError::Config(format!("--top must be a positive integer, got '{v}'"))
                })?;
                parsed.top = Some(n);
            }
            "--min-severity" => {
                let v = it
                    .next()
                    .ok_or_else(|| AxError::Config("--min-severity requires a level".into()))?;
                let s = parse_severity(v).ok_or_else(|| {
                    AxError::Config(format!(
                        "--min-severity must be one of info|low|medium|high|critical, got '{v}'"
                    ))
                })?;
                parsed.min_severity = Some(s);
            }
            "--no-column-roles" => {
                parsed.no_column_roles = true;
            }
            "--columns" => {
                let v = it.next().ok_or_else(|| {
                    AxError::Config("--columns requires a comma-separated list".into())
                })?;
                let cols = parse_column_list(v);
                if cols.is_empty() {
                    return Err(AxError::Config(
                        "--columns requires at least one column name".into(),
                    ));
                }
                parsed.columns = Some(cols);
            }
            "--exclude" => {
                let v = it.next().ok_or_else(|| {
                    AxError::Config("--exclude requires a comma-separated list".into())
                })?;
                let cols = parse_column_list(v);
                if cols.is_empty() {
                    return Err(AxError::Config(
                        "--exclude requires at least one column name".into(),
                    ));
                }
                parsed.exclude = Some(cols);
            }
            _ => parsed.positional.push(arg.clone()),
        }
    }
    if parsed.columns.is_some() && parsed.exclude.is_some() {
        return Err(AxError::Config(
            "use --columns or --exclude, not both".into(),
        ));
    }
    Ok(parsed)
}

/// Applies any `--columns`/`--exclude` projection to a record set before
/// detection. When `validate` is set (the primary corpus), an unknown column
/// name is a hard error (exit 2) — a typo must never silently scope the scan
/// down to nothing and read as "clean". The baseline is projected leniently
/// (`validate = false`): it is a different corpus and need not carry every
/// scoped column.
fn scope_columns(rs: RecordSet, args: &ScanArgs, validate: bool) -> Result<RecordSet, AxError> {
    if validate {
        if let Some(names) = args.columns.as_ref().or(args.exclude.as_ref()) {
            for n in names {
                if rs.column(n).is_none() {
                    return Err(AxError::Config(format!("no such column '{n}'")));
                }
            }
        }
    }
    Ok(match (&args.columns, &args.exclude) {
        (Some(keep), _) => rs.select(keep),
        (_, Some(drop)) => rs.without(drop),
        _ => rs,
    })
}

/// Builds the detector config, applying any `--period` / `--cadence` /
/// `--cad-max-cv` overrides. The cadence threshold defaults to the config
/// default when not given; because it is part of the config-version
/// fingerprint, overriding it is a visible, versioned change in the envelope.
fn config_for(args: &ScanArgs) -> DetectConfig {
    let defaults = DetectConfig::default();
    DetectConfig {
        ctx_period: args.period.unwrap_or(0),
        cadence_column: args.cadence.clone(),
        cad_max_cv: args.cad_max_cv.unwrap_or(defaults.cad_max_cv),
        point_fdr_q: args.fdr,
        column_roles: !args.no_column_roles,
        ..defaults
    }
}

/// Reads the input corpus: a path argument, or stdin when absent or `-`.
fn read_input(path: Option<&String>) -> Result<(String, Vec<u8>), AxError> {
    match path {
        Some(p) if p != "-" => {
            let bytes = std::fs::read(p).map_err(|e| AxError::Io(format!("{p}: {e}")))?;
            Ok((p.clone(), bytes))
        }
        _ => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| AxError::Io(format!("stdin: {e}")))?;
            Ok(("-".to_string(), buf))
        }
    }
}

/// Normalizes the optional baseline corpus from its path.
fn load_baseline(path: &Option<String>) -> Result<Option<RecordSet>, AxError> {
    match path {
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| AxError::Io(format!("{p}: {e}")))?;
            Ok(Some(ax_normalize::normalize(p, &bytes)?))
        }
        None => Ok(None),
    }
}

fn cmd_scan(rest: &[String]) -> Result<ExitCode, AxError> {
    let args = parse_scan_args(rest)?;
    let (source, bytes) = read_input(args.positional.first())?;
    let rs = scope_columns(ax_normalize::normalize(&source, &bytes)?, &args, true)?;
    let baseline = load_baseline(&args.baseline)?
        .map(|b| scope_columns(b, &args, false))
        .transpose()?;

    let cfg = config_for(&args);
    let ctx = match &baseline {
        Some(b) => ScanContext::compared(b, &rs),
        None => ScanContext::single(&rs),
    };
    let report = Registry::default_set().run(&ctx, &cfg);

    // Classify and report every scanned column's role (transparency), regardless
    // of whether role-based skipping is enabled.
    let roles: Vec<ColumnRole> = rs
        .columns
        .iter()
        .map(|c| ColumnRole {
            column: c.name.clone(),
            role: c.role(),
        })
        .collect();
    let mut builder = EnvelopeBuilder::new(cfg.version(), &rs.source, &rs.format, rs.rows())
        .findings(report.findings)
        .roles(roles);
    if let Some(b) = &baseline {
        builder = builder.baseline(b.source.clone());
    }
    for a in report.absent {
        builder = builder.absent(a.detector, a.reason);
    }
    // Output scoping: cap / floor the emitted findings. summary + exit still
    // reflect everything detected, so this never hides that anomalies exist.
    if let Some(s) = args.min_severity {
        builder = builder.min_severity(s);
    }
    if let Some(n) = args.top {
        builder = builder.top(n);
    }
    let env = builder.build();

    println!(
        "{}",
        serde_json::to_string(&env).expect("envelope serializes")
    );
    Ok(if env.exit == ExitCode::Anomalies.code() {
        ExitCode::Anomalies
    } else {
        ExitCode::Clean
    })
}

fn cmd_explain(rest: &[String]) -> Result<ExitCode, AxError> {
    let args = parse_scan_args(rest)?;
    let handle_str = args
        .positional
        .first()
        .ok_or_else(|| AxError::Config("explain requires a <HANDLE> argument".into()))?;
    let handle = Handle::parse(handle_str).ok_or_else(|| AxError::BadHandle(handle_str.clone()))?;

    let (source, bytes) = read_input(args.positional.get(1))?;
    let rs = scope_columns(ax_normalize::normalize(&source, &bytes)?, &args, true)?;
    let baseline = load_baseline(&args.baseline)?
        .map(|b| scope_columns(b, &args, false))
        .transpose()?;

    let evidence = resolve_handle(&rs, &handle)?;

    // Re-run detection and attach any findings that point at this handle.
    let cfg = config_for(&args);
    let ctx = match &baseline {
        Some(b) => ScanContext::compared(b, &rs),
        None => ScanContext::single(&rs),
    };
    let report = Registry::default_set().run(&ctx, &cfg);
    let findings: Vec<_> = report
        .findings
        .into_iter()
        .filter(|f| f.handle == handle)
        .collect();

    let out = serde_json::json!({
        "protocol": PROTOCOL,
        "handle": handle_str,
        "evidence": evidence,
        "findings": findings,
    });
    println!(
        "{}",
        serde_json::to_string(&out).expect("explain serializes")
    );
    Ok(ExitCode::Clean)
}

/// Resolves a handle to a compact evidence object, or fails cleanly if it does
/// not address anything in this corpus (honest absence, never a fabricated hit).
fn resolve_handle(rs: &RecordSet, handle: &Handle) -> Result<serde_json::Value, AxError> {
    let unresolved = || AxError::UnresolvedHandle(handle.canonical());
    match handle {
        Handle::Column { name } | Handle::Dist { column: name } => {
            let col = rs.column(name).ok_or_else(unresolved)?;
            Ok(serde_json::json!({
                "kind": "column",
                "column": col.name,
                "type": col.ty,
                "len": col.len(),
                "nulls": col.null_count(),
            }))
        }
        Handle::Cell { column, row } => {
            let col = rs.column(column).ok_or_else(unresolved)?;
            let value: &Value = col.cells.get(*row).ok_or_else(unresolved)?;
            Ok(serde_json::json!({
                "kind": "cell",
                "column": col.name,
                "row": row,
                "value": value,
                "column_type": col.ty,
            }))
        }
        Handle::Range { column, start, end } => {
            let col = rs.column(column).ok_or_else(unresolved)?;
            if *start >= *end || *end > col.len() {
                return Err(unresolved());
            }
            Ok(serde_json::json!({
                "kind": "range",
                "column": col.name,
                "start": start,
                "end": end,
                "values": &col.cells[*start..*end],
            }))
        }
        Handle::Row { row } => {
            if *row >= rs.rows() {
                return Err(unresolved());
            }
            let cells: serde_json::Map<String, serde_json::Value> = rs
                .columns
                .iter()
                .map(|c| {
                    (
                        c.name.clone(),
                        serde_json::to_value(&c.cells[*row]).unwrap(),
                    )
                })
                .collect();
            Ok(serde_json::json!({
                "kind": "row",
                "row": row,
                "cells": cells,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::Column;

    fn corpus() -> RecordSet {
        RecordSet::new(
            "-",
            "csv",
            vec![Column::new(
                "x",
                vec![Value::Int(1), Value::Int(2), Value::Int(3)],
            )],
        )
    }

    #[test]
    fn resolve_cell_ok() {
        let rs = corpus();
        let h = Handle::Cell {
            column: "x".into(),
            row: 1,
        };
        let ev = resolve_handle(&rs, &h).unwrap();
        assert_eq!(ev["value"], serde_json::json!({"t": "int", "v": 2}));
    }

    #[test]
    fn resolve_out_of_range_is_unresolved() {
        let rs = corpus();
        let h = Handle::Cell {
            column: "x".into(),
            row: 99,
        };
        assert!(matches!(
            resolve_handle(&rs, &h),
            Err(AxError::UnresolvedHandle(_))
        ));
    }

    #[test]
    fn resolve_missing_column_is_unresolved() {
        let rs = corpus();
        let h = Handle::Column {
            name: "nope".into(),
        };
        assert!(matches!(
            resolve_handle(&rs, &h),
            Err(AxError::UnresolvedHandle(_))
        ));
    }

    #[test]
    fn resolve_range_valid_and_invalid() {
        let rs = corpus(); // 3 rows
                           // valid [0,2)
        let ok = resolve_handle(
            &rs,
            &Handle::Range {
                column: "x".into(),
                start: 0,
                end: 2,
            },
        )
        .unwrap();
        assert_eq!(ok["values"].as_array().unwrap().len(), 2);
        // empty/inverted range start >= end
        assert!(resolve_handle(
            &rs,
            &Handle::Range {
                column: "x".into(),
                start: 2,
                end: 2
            }
        )
        .is_err());
        assert!(resolve_handle(
            &rs,
            &Handle::Range {
                column: "x".into(),
                start: 3,
                end: 1
            }
        )
        .is_err());
        // end past column length
        assert!(resolve_handle(
            &rs,
            &Handle::Range {
                column: "x".into(),
                start: 0,
                end: 4
            }
        )
        .is_err());
        // exact end == len is valid
        assert!(resolve_handle(
            &rs,
            &Handle::Range {
                column: "x".into(),
                start: 0,
                end: 3
            }
        )
        .is_ok());
    }

    #[test]
    fn resolve_row_ok_and_out_of_range() {
        let rs = corpus(); // column "x", 3 rows
        let ev = resolve_handle(&rs, &Handle::Row { row: 1 }).unwrap();
        assert_eq!(ev["kind"], "row");
        assert_eq!(ev["cells"]["x"], serde_json::json!({"t": "int", "v": 2}));
        // a row at or past the row count does not resolve
        assert!(matches!(
            resolve_handle(&rs, &Handle::Row { row: 3 }),
            Err(AxError::UnresolvedHandle(_))
        ));
    }

    #[test]
    fn usage_is_nonempty_and_documents_verbs() {
        let u = usage();
        assert!(u.contains("describe") && u.contains("scan") && u.contains("explain"));
    }

    #[test]
    fn unknown_command_errors() {
        assert!(run(&["frobnicate".to_string()]).is_err());
    }

    fn strings(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_scan_args_extracts_flags_and_positionals() {
        let a = parse_scan_args(&strings(&[
            "--baseline",
            "base.csv",
            "--period",
            "7",
            "--cadence",
            "ts",
            "cur.csv",
        ]))
        .unwrap();
        assert_eq!(a.baseline, Some("base.csv".to_string()));
        assert_eq!(a.period, Some(7));
        assert_eq!(a.cadence, Some("ts".to_string()));
        assert_eq!(a.positional, strings(&["cur.csv"]));
    }

    #[test]
    fn parse_scan_args_defaults_when_flags_absent() {
        let a = parse_scan_args(&strings(&["cur.csv"])).unwrap();
        assert_eq!(a.baseline, None);
        assert_eq!(a.period, None);
        assert_eq!(a.positional, strings(&["cur.csv"]));
    }

    #[test]
    fn parse_scan_args_errors_on_bad_flag_values() {
        assert!(parse_scan_args(&strings(&["--baseline"])).is_err());
        assert!(parse_scan_args(&strings(&["--period"])).is_err());
        assert!(parse_scan_args(&strings(&["--period", "notanumber"])).is_err());
    }

    #[test]
    fn parse_scan_args_parses_and_validates_fdr() {
        let a = parse_scan_args(&strings(&["--fdr", "0.05", "x.csv"])).unwrap();
        assert_eq!(a.fdr, Some(0.05));
        assert_eq!(config_for(&a).point_fdr_q, Some(0.05));
        // q = 1.0 is the inclusive upper bound (valid); default has no FDR.
        assert_eq!(
            parse_scan_args(&strings(&["--fdr", "1"])).unwrap().fdr,
            Some(1.0)
        );
        assert_eq!(config_for(&ScanArgs::default()).point_fdr_q, None);
        // missing, non-numeric, and out-of-range (≤0, >1, non-finite) are rejected
        assert!(parse_scan_args(&strings(&["--fdr"])).is_err());
        assert!(parse_scan_args(&strings(&["--fdr", "high"])).is_err());
        assert!(parse_scan_args(&strings(&["--fdr", "0"])).is_err());
        assert!(parse_scan_args(&strings(&["--fdr", "-0.1"])).is_err());
        assert!(parse_scan_args(&strings(&["--fdr", "1.5"])).is_err());
        assert!(parse_scan_args(&strings(&["--fdr", "inf"])).is_err());
    }

    #[test]
    fn no_column_roles_flag_toggles_config() {
        let a = parse_scan_args(&strings(&["--no-column-roles", "x.csv"])).unwrap();
        assert!(a.no_column_roles);
        assert!(!config_for(&a).column_roles);
        // default: roles on
        assert!(
            !parse_scan_args(&strings(&["x.csv"]))
                .unwrap()
                .no_column_roles
        );
        assert!(config_for(&ScanArgs::default()).column_roles);
    }

    #[test]
    fn parse_scan_args_parses_and_validates_top() {
        assert_eq!(
            parse_scan_args(&strings(&["--top", "50", "x.csv"]))
                .unwrap()
                .top,
            Some(50)
        );
        // missing, non-numeric, and zero are rejected (zero would emit nothing)
        assert!(parse_scan_args(&strings(&["--top"])).is_err());
        assert!(parse_scan_args(&strings(&["--top", "lots"])).is_err());
        assert!(parse_scan_args(&strings(&["--top", "0"])).is_err());
    }

    #[test]
    fn parse_scan_args_parses_and_validates_min_severity() {
        let a = parse_scan_args(&strings(&["--min-severity", "High", "x.csv"])).unwrap();
        assert_eq!(a.min_severity, Some(Severity::High));
        // case-insensitive across the whole ladder
        for (s, want) in [
            ("info", Severity::Info),
            ("low", Severity::Low),
            ("MEDIUM", Severity::Medium),
            ("critical", Severity::Critical),
        ] {
            assert_eq!(parse_severity(s), Some(want));
        }
        assert!(parse_scan_args(&strings(&["--min-severity"])).is_err());
        assert!(parse_scan_args(&strings(&["--min-severity", "extreme"])).is_err());
    }

    #[test]
    fn parse_column_list_trims_and_drops_empties() {
        assert_eq!(parse_column_list("a, b ,c"), strings(&["a", "b", "c"]));
        // surrounding/empty entries are dropped, not kept as ""
        assert_eq!(parse_column_list(",a,,"), strings(&["a"]));
        assert!(parse_column_list(" , ").is_empty());
    }

    #[test]
    fn parse_scan_args_parses_columns_and_exclude() {
        let a = parse_scan_args(&strings(&["--columns", "p,q", "cur.csv"])).unwrap();
        assert_eq!(a.columns, Some(strings(&["p", "q"])));
        assert_eq!(a.exclude, None);
        let b = parse_scan_args(&strings(&["--exclude", "noise", "cur.csv"])).unwrap();
        assert_eq!(b.exclude, Some(strings(&["noise"])));
        assert_eq!(b.columns, None);
    }

    #[test]
    fn parse_scan_args_rejects_columns_and_exclude_together() {
        assert!(parse_scan_args(&strings(&["--columns", "a", "--exclude", "b"])).is_err());
    }

    #[test]
    fn parse_scan_args_rejects_missing_or_empty_column_lists() {
        assert!(parse_scan_args(&strings(&["--columns"])).is_err());
        assert!(parse_scan_args(&strings(&["--exclude"])).is_err());
        assert!(parse_scan_args(&strings(&["--columns", " , "])).is_err());
        assert!(parse_scan_args(&strings(&["--exclude", ","])).is_err());
    }

    fn abc() -> RecordSet {
        RecordSet::new(
            "-",
            "csv",
            vec![
                Column::new("a", vec![Value::Int(1), Value::Int(2)]),
                Column::new("b", vec![Value::Int(3), Value::Int(4)]),
                Column::new("c", vec![Value::Int(5), Value::Int(6)]),
            ],
        )
    }

    #[test]
    fn scope_columns_select_keeps_only_named() {
        let args = ScanArgs {
            columns: Some(strings(&["a", "c"])),
            ..ScanArgs::default()
        };
        let rs = scope_columns(abc(), &args, true).unwrap();
        let names: Vec<&str> = rs.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
    }

    #[test]
    fn scope_columns_exclude_drops_named() {
        let args = ScanArgs {
            exclude: Some(strings(&["b"])),
            ..ScanArgs::default()
        };
        let rs = scope_columns(abc(), &args, true).unwrap();
        let names: Vec<&str> = rs.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "c"]);
    }

    #[test]
    fn scope_columns_validates_unknown_name_on_primary() {
        // A typo'd column on the primary corpus is a hard error, never a silent
        // empty scan that reads as "clean".
        let args = ScanArgs {
            columns: Some(strings(&["a", "typo"])),
            ..ScanArgs::default()
        };
        assert!(scope_columns(abc(), &args, true).is_err());
        // The same unknown name on the baseline (validate = false) is tolerated:
        // a different corpus need not carry every scoped column.
        let scoped = scope_columns(abc(), &args, false).unwrap();
        let names: Vec<&str> = scoped.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a"]);
    }

    #[test]
    fn scope_columns_unknown_exclude_name_also_validated() {
        let args = ScanArgs {
            exclude: Some(strings(&["typo"])),
            ..ScanArgs::default()
        };
        assert!(scope_columns(abc(), &args, true).is_err());
    }

    #[test]
    fn scope_columns_noop_without_flags() {
        let rs = scope_columns(abc(), &ScanArgs::default(), true).unwrap();
        assert_eq!(rs.width(), 3);
    }

    #[test]
    fn config_for_applies_period_override() {
        let a = ScanArgs {
            period: Some(24),
            ..ScanArgs::default()
        };
        assert_eq!(config_for(&a).ctx_period, 24);
        // no --period ⇒ disabled (0)
        assert_eq!(config_for(&ScanArgs::default()).ctx_period, 0);

        // --cadence threads through to the config column
        let c = ScanArgs {
            cadence: Some("ts".into()),
            ..ScanArgs::default()
        };
        assert_eq!(config_for(&c).cadence_column.as_deref(), Some("ts"));
        assert_eq!(config_for(&ScanArgs::default()).cadence_column, None);
    }

    #[test]
    fn config_for_applies_cad_max_cv_override() {
        let a = ScanArgs {
            cad_max_cv: Some(0.15),
            ..ScanArgs::default()
        };
        assert_eq!(config_for(&a).cad_max_cv, 0.15);
        // no flag ⇒ the config default is used, not 0.0
        assert_eq!(
            config_for(&ScanArgs::default()).cad_max_cv,
            DetectConfig::default().cad_max_cv
        );
        // overriding the threshold changes the config-version fingerprint
        assert_ne!(
            config_for(&a).version(),
            config_for(&ScanArgs::default()).version()
        );
    }

    #[test]
    fn parse_scan_args_parses_and_validates_cad_max_cv() {
        let a = parse_scan_args(&strings(&["--cad-max-cv", "0.15", "x.pcap"])).unwrap();
        assert_eq!(a.cad_max_cv, Some(0.15));
        // zero is the boundary: a 0.0 threshold is valid (flag only perfectly
        // regular timing), so the bound is `< 0.0`, not `<= 0.0`.
        assert_eq!(
            parse_scan_args(&strings(&["--cad-max-cv", "0"]))
                .unwrap()
                .cad_max_cv,
            Some(0.0)
        );
        // missing value, non-numeric, negative, and non-finite are all rejected
        assert!(parse_scan_args(&strings(&["--cad-max-cv"])).is_err());
        assert!(parse_scan_args(&strings(&["--cad-max-cv", "lots"])).is_err());
        assert!(parse_scan_args(&strings(&["--cad-max-cv", "-0.1"])).is_err());
        assert!(parse_scan_args(&strings(&["--cad-max-cv", "inf"])).is_err());
        assert!(parse_scan_args(&strings(&["--cad-max-cv", "NaN"])).is_err());
    }
}
