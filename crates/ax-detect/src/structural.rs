//! Structural anomaly detector.
//!
//! Structural anomalies are about *shape*, not values:
//!
//! - **Single corpus** (always runs): columns with conflicting cell types
//!   (`Mixed`), and columns whose null fraction exceeds a threshold.
//! - **With a baseline**: schema diff — columns added, columns dropped, and
//!   columns whose inferred type changed between baseline and current.
//!
//! Because it can always assess the current corpus's shape, this detector never
//! reports absence; it simply emits fewer findings when there is no baseline.

use crate::config::DetectConfig;
use crate::{calibrate, Detector, Report, ScanContext};
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, ColType, Finding, RecordSet};

#[derive(Debug, Default, Clone)]
pub struct SchemaDetector;

impl SchemaDetector {
    fn col_handle(name: &str) -> Handle {
        Handle::Column {
            name: name.to_string(),
        }
    }

    /// Single-corpus shape checks: mixed types and excessive nulls.
    fn check_shape(&self, current: &RecordSet, cfg: &DetectConfig, out: &mut Report) {
        for col in &current.columns {
            if col.ty == ColType::Mixed {
                out.push(
                    Finding::new(
                        self.id(),
                        AnomalyClass::Structural,
                        Self::col_handle(&col.name),
                        0.7,
                        0.0,
                        format!("column '{}' mixes conflicting cell types", col.name),
                    )
                    .with_col_type(ColType::Mixed),
                );
            }
            if col.is_empty() {
                continue;
            }
            let frac = col.null_count() as f64 / col.len() as f64;
            if frac > cfg.struct_null_rate {
                out.push(
                    Finding::new(
                        self.id(),
                        AnomalyClass::Structural,
                        Self::col_handle(&col.name),
                        calibrate::from_exceedance(frac, cfg.struct_null_rate),
                        frac,
                        format!("column '{}' is {:.0}% null", col.name, frac * 100.0),
                    )
                    .with_col_type(col.ty),
                );
            }
        }
    }

    /// Baseline schema diff: added/dropped columns and type changes.
    fn check_schema_diff(&self, current: &RecordSet, baseline: &RecordSet, out: &mut Report) {
        for col in &current.columns {
            match baseline.column(&col.name) {
                None => out.push(
                    Finding::new(
                        self.id(),
                        AnomalyClass::Structural,
                        Self::col_handle(&col.name),
                        0.9,
                        1.0,
                        format!("column '{}' is new (absent in baseline)", col.name),
                    )
                    .with_col_type(col.ty),
                ),
                Some(bcol) if bcol.ty != col.ty => out.push(
                    Finding::new(
                        self.id(),
                        AnomalyClass::Structural,
                        Self::col_handle(&col.name),
                        0.85,
                        1.0,
                        format!(
                            "column '{}' type changed {:?} → {:?}",
                            col.name, bcol.ty, col.ty
                        ),
                    )
                    .with_col_type(col.ty),
                ),
                Some(_) => {}
            }
        }
        for bcol in &baseline.columns {
            if current.column(&bcol.name).is_none() {
                out.push(
                    Finding::new(
                        self.id(),
                        AnomalyClass::Structural,
                        Self::col_handle(&bcol.name),
                        0.9,
                        1.0,
                        format!("column '{}' was dropped (present in baseline)", bcol.name),
                    )
                    .with_col_type(bcol.ty),
                );
            }
        }
    }
}

impl Detector for SchemaDetector {
    fn id(&self) -> &'static str {
        "struct.schema"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Structural
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        self.check_shape(ctx.current, cfg, out);
        if let Some(baseline) = ctx.baseline {
            self.check_schema_diff(ctx.current, baseline, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::{Column, Value};

    fn rs(cols: Vec<Column>) -> RecordSet {
        RecordSet::new("-", "t", cols)
    }

    fn run(ctx: &ScanContext) -> Report {
        let mut out = Report::new();
        SchemaDetector.detect(ctx, &DetectConfig::default(), &mut out);
        out
    }

    #[test]
    fn clean_single_corpus_has_no_findings_and_no_absence() {
        let r = rs(vec![Column::new("x", vec![Value::Int(1), Value::Int(2)])]);
        let report = run(&ScanContext::single(&r));
        assert!(report.findings.is_empty());
        assert!(report.absent.is_empty(), "structural detector always runs");
    }

    #[test]
    fn mixed_type_column_is_flagged() {
        let r = rs(vec![Column::new(
            "x",
            vec![Value::Int(1), Value::Str("oops".into()), Value::Bool(true)],
        )]);
        let report = run(&ScanContext::single(&r));
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].reason.contains("conflicting"));
    }

    #[test]
    fn high_null_rate_is_flagged_low_is_not() {
        // 3/4 null > 0.5 → flagged
        let r = rs(vec![Column::new(
            "x",
            vec![Value::Int(1), Value::Null, Value::Null, Value::Null],
        )]);
        let report = run(&ScanContext::single(&r));
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].score > 0.5);

        // 1/4 null < 0.5 → clean
        let r2 = rs(vec![Column::new(
            "x",
            vec![Value::Int(1), Value::Int(2), Value::Int(3), Value::Null],
        )]);
        assert!(run(&ScanContext::single(&r2)).findings.is_empty());

        // exactly 2/4 = 0.5 is NOT > 0.5 → clean (pins the strict comparator)
        let r3 = rs(vec![Column::new(
            "x",
            vec![Value::Int(1), Value::Int(2), Value::Null, Value::Null],
        )]);
        assert!(run(&ScanContext::single(&r3)).findings.is_empty());
    }

    #[test]
    fn added_and_dropped_columns_detected() {
        let base = rs(vec![
            Column::new("a", vec![Value::Int(1)]),
            Column::new("gone", vec![Value::Int(2)]),
        ]);
        let cur = rs(vec![
            Column::new("a", vec![Value::Int(1)]),
            Column::new("fresh", vec![Value::Int(9)]),
        ]);
        let report = run(&ScanContext::compared(&base, &cur));
        let reasons: Vec<&str> = report.findings.iter().map(|f| f.reason.as_str()).collect();
        assert!(reasons.iter().any(|r| r.contains("'fresh' is new")));
        assert!(reasons.iter().any(|r| r.contains("'gone' was dropped")));
    }

    #[test]
    fn type_change_detected() {
        let base = rs(vec![Column::new("v", vec![Value::Int(1), Value::Int(2)])]);
        let cur = rs(vec![Column::new(
            "v",
            vec![Value::Str("a".into()), Value::Str("b".into())],
        )]);
        let report = run(&ScanContext::compared(&base, &cur));
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].reason.contains("type changed"));
    }

    #[test]
    fn matching_schema_yields_no_schema_findings() {
        let base = rs(vec![Column::new("v", vec![Value::Int(1), Value::Int(2)])]);
        let cur = rs(vec![Column::new("v", vec![Value::Int(5), Value::Int(6)])]);
        assert!(run(&ScanContext::compared(&base, &cur)).findings.is_empty());
    }
}
