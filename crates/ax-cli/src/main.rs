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
use ax_core::finding::Handle;
use ax_core::{AxError, RecordSet, Value};
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
     \x20 anomalyx scan [--baseline B] [PATH]       Scan a file (or stdin) for anomalies\n\
     \x20 anomalyx explain <HANDLE> [--baseline B] [PATH]   Resolve a finding handle\n\
     \n\
     With --baseline, distributional drift and schema-diff are compared against B.\n\
     EXIT: 0 clean · 1 anomalies found · 2 error"
}

/// Parsed scan/explain arguments: optional `--baseline <PATH>`, optional
/// `--period <N>`, and the remaining positionals. Fails cleanly on a flag with a
/// missing or malformed value.
#[derive(Debug, Default, PartialEq)]
struct ScanArgs {
    baseline: Option<String>,
    period: Option<usize>,
    positional: Vec<String>,
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
            _ => parsed.positional.push(arg.clone()),
        }
    }
    Ok(parsed)
}

/// Builds the detector config, applying any `--period` override.
fn config_for(args: &ScanArgs) -> DetectConfig {
    DetectConfig {
        ctx_period: args.period.unwrap_or(0),
        ..DetectConfig::default()
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
    let rs = ax_normalize::normalize(&source, &bytes)?;
    let baseline = load_baseline(&args.baseline)?;

    let cfg = config_for(&args);
    let ctx = match &baseline {
        Some(b) => ScanContext::compared(b, &rs),
        None => ScanContext::single(&rs),
    };
    let report = Registry::default_set().run(&ctx, &cfg);

    let mut builder = EnvelopeBuilder::new(cfg.version(), &rs.source, &rs.format, rs.rows())
        .findings(report.findings);
    if let Some(b) = &baseline {
        builder = builder.baseline(b.source.clone());
    }
    for a in report.absent {
        builder = builder.absent(a.detector, a.reason);
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
    let rs = ax_normalize::normalize(&source, &bytes)?;
    let baseline = load_baseline(&args.baseline)?;

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
            "cur.csv",
        ]))
        .unwrap();
        assert_eq!(a.baseline, Some("base.csv".to_string()));
        assert_eq!(a.period, Some(7));
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
    fn config_for_applies_period_override() {
        let a = ScanArgs {
            period: Some(24),
            ..ScanArgs::default()
        };
        assert_eq!(config_for(&a).ctx_period, 24);
        // no --period ⇒ disabled (0)
        assert_eq!(config_for(&ScanArgs::default()).ctx_period, 0);
    }
}
