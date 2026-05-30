//! End-to-end contract tests: drive the compiled `anomalyx` binary exactly as
//! an agent would. These exercise the IO/orchestration layer (`main`,
//! `read_input`, `cmd_scan`, `cmd_explain`) that unit tests cannot reach, and
//! pin the committed exit codes the article insists on.

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the binary under test, provided by Cargo for integration tests.
const BIN: &str = env!("CARGO_BIN_EXE_anomalyx");

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs `anomalyx <args>` with `stdin` piped in, returning code and streams.
fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn anomalyx");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    Output {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

const CLEAN: &[u8] = b"id,amount\n1,10\n2,11\n3,9\n4,10\n5,12\n6,11\n7,10\n8,9\n";
const OUTLIER: &[u8] = b"id,amount\n1,10\n2,11\n3,9\n4,10\n5,12\n6,11\n7,10\n8,9\n9,9999\n";

#[test]
fn describe_succeeds_and_emits_protocol() {
    let o = run(&["describe"], b"");
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("anomalyx/tq1"));
    assert!(o.stdout.contains("point.modz"));
}

#[test]
fn schema_succeeds_and_is_json() {
    let o = run(&["schema"], b"");
    assert_eq!(o.code, 0);
    let v: serde_json::Value = serde_json::from_str(&o.stdout).expect("schema is JSON");
    assert_eq!(
        v["properties"]["exit"]["enum"],
        serde_json::json!([0, 1, 2])
    );
}

#[test]
fn scan_clean_exits_zero_with_no_rows() {
    let o = run(&["scan"], CLEAN);
    assert_eq!(o.code, 0, "stderr: {}", o.stderr);
    let v: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["exit"], 0);
    assert_eq!(v["rows"].as_array().unwrap().len(), 0);
}

#[test]
fn scan_outlier_exits_one_with_a_finding() {
    let o = run(&["scan"], OUTLIER);
    assert_eq!(o.code, 1, "stderr: {}", o.stderr);
    let v: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["exit"], 1);
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);
    // the handle string is interned in the dict
    assert!(v["dict"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == "cell:amount:8"));
}

#[test]
fn scan_reads_from_a_file_path_not_stdin() {
    // Write a file with an OUTLIER, but pipe CLEAN to stdin. If the tool honors
    // the path argument it exits 1; if it wrongly read stdin it would exit 0.
    let dir = std::env::temp_dir();
    let path = dir.join("anomalyx_cli_test_outlier.csv");
    std::fs::write(&path, OUTLIER).unwrap();
    let o = run(&["scan", path.to_str().unwrap()], CLEAN);
    let _ = std::fs::remove_file(&path);
    assert_eq!(o.code, 1, "must read the file, stderr: {}", o.stderr);
}

#[test]
fn scan_dash_reads_stdin() {
    // Explicit "-" path must read stdin (here, an outlier) → exit 1.
    let o = run(&["scan", "-"], OUTLIER);
    assert_eq!(o.code, 1, "stderr: {}", o.stderr);
}

#[test]
fn explain_resolves_a_cell_handle() {
    let o = run(&["explain", "cell:amount:8", "-"], OUTLIER);
    assert_eq!(o.code, 0, "stderr: {}", o.stderr);
    let v: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(
        v["evidence"]["value"],
        serde_json::json!({"t": "int", "v": 9999})
    );
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn explain_bad_handle_exits_error() {
    let o = run(&["explain", "not-a-handle", "-"], OUTLIER);
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("malformed handle"));
}

#[test]
fn scan_baseline_mode_detects_drift() {
    let dir = std::env::temp_dir();
    let base = dir.join("anomalyx_base.csv");
    let cur = dir.join("anomalyx_cur.csv");
    // 24 rows each; a hard distribution shift in `amount`.
    let mut b = String::from("amount\n");
    let mut c = String::from("amount\n");
    for i in 0..24 {
        b.push_str(&format!("{}\n", 10 + i % 5));
        c.push_str(&format!("{}\n", 900 + i % 5));
    }
    std::fs::write(&base, &b).unwrap();
    std::fs::write(&cur, &c).unwrap();
    let o = run(
        &[
            "scan",
            "--baseline",
            base.to_str().unwrap(),
            cur.to_str().unwrap(),
        ],
        b"",
    );
    let _ = std::fs::remove_file(&base);
    let _ = std::fs::remove_file(&cur);
    assert_eq!(o.code, 1, "stderr: {}", o.stderr);
    let v: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["baseline"].as_str().unwrap(), base.to_str().unwrap());
    // KS and PSI should both fire on the shifted column.
    let detectors: Vec<&str> = v["dict"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    assert!(detectors.contains(&"dist.ks"));
    assert!(detectors.contains(&"dist.psi"));
}

#[test]
fn scan_without_baseline_marks_distributional_absent() {
    let o = run(&["scan"], CLEAN);
    assert_eq!(o.code, 0);
    let v: serde_json::Value = serde_json::from_str(&o.stdout).unwrap();
    assert!(
        v.get("baseline").is_none(),
        "no baseline field in single mode"
    );
    let absent: Vec<&str> = v["absent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["detector"].as_str().unwrap())
        .collect();
    assert!(absent.contains(&"dist.ks"));
}

#[test]
fn no_args_exits_error() {
    let o = run(&[], b"");
    assert_eq!(o.code, 2);
}

#[test]
fn unknown_command_exits_error() {
    let o = run(&["frobnicate"], b"");
    assert_eq!(o.code, 2);
}
