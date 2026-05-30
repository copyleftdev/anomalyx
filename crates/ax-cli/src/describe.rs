//! `anomalyx describe` — the protocol's self-description.
//!
//! An agent runs this first to learn what the tool is, which formats it
//! ingests, which detectors and anomaly classes exist, the exit-code semantics,
//! and the current deterministic config fingerprint. Everything here is derived
//! from the same registries `scan` uses, so the description can never drift from
//! behavior.

use ax_core::envelope::{ExitCode, FINDING_COLUMNS, PROTOCOL};
use ax_core::AnomalyClass;
use ax_detect::{DetectConfig, Registry};

pub fn describe_json() -> String {
    let cfg = DetectConfig::default();
    let classes: Vec<&str> = AnomalyClass::ALL.iter().map(|c| c.token()).collect();
    let detectors = Registry::default_set().ids();

    let doc = serde_json::json!({
        "protocol": PROTOCOL,
        "tool": "anomalyx",
        "summary": "Contract-first anomaly detection over arbitrary corpora.",
        "commands": {
            "describe": "Emit this protocol metadata.",
            "schema": "Emit the JSON Schema of `scan` output.",
            "scan": "Normalize input (file or stdin) and emit a tq1 anomaly envelope.",
            "explain": "Resolve a finding handle to its underlying evidence."
        },
        "input_formats": ["csv", "tsv", "ndjson", "json"],
        "planned_formats": ["parquet", "arrow"],
        "anomaly_classes": classes,
        "detectors": detectors,
        "finding_columns": FINDING_COLUMNS,
        "exit_codes": {
            "clean": ExitCode::Clean.code(),
            "anomalies": ExitCode::Anomalies.code(),
            "error": ExitCode::Error.code()
        },
        "config": cfg,
        "config_version": cfg.version(),
        "determinism": "Same input + same config_version yields byte-identical output."
    });
    serde_json::to_string_pretty(&doc).expect("describe serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_is_valid_json_with_protocol() {
        let v: serde_json::Value = serde_json::from_str(&describe_json()).unwrap();
        assert_eq!(v["protocol"], PROTOCOL);
        assert!(v["detectors"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("point.modz")));
        assert_eq!(v["exit_codes"]["anomalies"], 1);
    }
}
