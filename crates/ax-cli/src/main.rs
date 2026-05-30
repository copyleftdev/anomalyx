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
use ax_detect::{DetectConfig, Registry};
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
     \x20 anomalyx describe            Protocol metadata\n\
     \x20 anomalyx schema              JSON Schema of scan output\n\
     \x20 anomalyx scan [PATH]         Scan a file (or stdin) for anomalies\n\
     \x20 anomalyx explain <HANDLE> [PATH]   Resolve a finding handle to evidence\n\
     \n\
     EXIT: 0 clean · 1 anomalies found · 2 error"
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

fn cmd_scan(rest: &[String]) -> Result<ExitCode, AxError> {
    let (source, bytes) = read_input(rest.first())?;
    let rs = ax_normalize::normalize(&source, &bytes)?;
    let cfg = DetectConfig::default();
    let registry = Registry::default_set();
    let report = registry.run(&rs, &cfg);

    let mut builder =
        EnvelopeBuilder::new(cfg.version(), &rs.source, &rs.format, rs.rows()).findings(report.findings);
    for a in report.absent {
        builder = builder.absent(a.detector, a.reason);
    }
    let env = builder.build();

    println!("{}", serde_json::to_string(&env).expect("envelope serializes"));
    Ok(if env.exit == ExitCode::Anomalies.code() {
        ExitCode::Anomalies
    } else {
        ExitCode::Clean
    })
}

fn cmd_explain(rest: &[String]) -> Result<ExitCode, AxError> {
    let handle_str = rest
        .first()
        .ok_or_else(|| AxError::Config("explain requires a <HANDLE> argument".into()))?;
    let handle =
        Handle::parse(handle_str).ok_or_else(|| AxError::BadHandle(handle_str.clone()))?;

    let (source, bytes) = read_input(rest.get(1))?;
    let rs = ax_normalize::normalize(&source, &bytes)?;

    let evidence = resolve_handle(&rs, &handle)?;

    // Re-run detection and attach any findings that point at this handle.
    let cfg = DetectConfig::default();
    let report = Registry::default_set().run(&rs, &cfg);
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
    println!("{}", serde_json::to_string(&out).expect("explain serializes"));
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
        let h = Handle::Cell { column: "x".into(), row: 1 };
        let ev = resolve_handle(&rs, &h).unwrap();
        assert_eq!(ev["value"], serde_json::json!({"t": "int", "v": 2}));
    }

    #[test]
    fn resolve_out_of_range_is_unresolved() {
        let rs = corpus();
        let h = Handle::Cell { column: "x".into(), row: 99 };
        assert!(matches!(
            resolve_handle(&rs, &h),
            Err(AxError::UnresolvedHandle(_))
        ));
    }

    #[test]
    fn resolve_missing_column_is_unresolved() {
        let rs = corpus();
        let h = Handle::Column { name: "nope".into() };
        assert!(matches!(
            resolve_handle(&rs, &h),
            Err(AxError::UnresolvedHandle(_))
        ));
    }

    #[test]
    fn unknown_command_errors() {
        assert!(run(&["frobnicate".to_string()]).is_err());
    }
}
