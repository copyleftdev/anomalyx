//! Golden-envelope snapshot tests — the contract's tripwire.
//!
//! These run the actual `anomalyx` binary and compare its stdout, byte-for-byte,
//! against committed golden files. They pin the *exact* wire output of the three
//! contract surfaces — `schema`, `describe`, and a representative `scan` envelope
//! — so any accidental drift (a renamed field, a changed dense-row layout, a
//! shifted `config_version`, a recalibrated confidence) fails CI as a visible
//! diff rather than slipping out in a release.
//!
//! Intentional changes are expected to update the goldens: regenerate with
//! `BLESS=1 cargo test -p anomalyx --test golden`.

use std::io::Write;
use std::process::{Command, Stdio};

/// Runs the built binary with `args`, feeding `stdin`, returning stdout as text.
fn run(args: &[&str], stdin: &[u8]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anomalyx"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn anomalyx");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

/// Compares `actual` to the committed golden `name`; `BLESS=1` rewrites it.
fn check_golden(name: &str, actual: &str) {
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("BLESS").is_some() {
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {path}; regenerate with BLESS=1"));
    assert!(
        actual == expected,
        "golden mismatch for {name}.\nIf this change is intentional, regenerate with \
         `BLESS=1 cargo test -p anomalyx --test golden`."
    );
}

/// A fixed corpus exercising column roles (`id` → identifier, skipped) and the
/// point detector (`reading` → one clear outlier). Piped via stdin so the
/// envelope's `source` is the stable `"-"`.
const SCAN_INPUT: &[u8] =
    b"id,reading\n1,10\n2,11\n3,9\n4,10\n5,12\n6,8\n7,11\n8,10\n9,9\n10,1000\n";

#[test]
fn golden_schema() {
    check_golden("schema.json", &run(&["schema"], b""));
}

#[test]
fn golden_describe() {
    check_golden("describe.json", &run(&["describe"], b""));
}

#[test]
fn golden_scan_basic() {
    check_golden("scan_basic.json", &run(&["scan"], SCAN_INPUT));
}
