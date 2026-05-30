//! Contextual anomaly detector (seasonal subseries).
//!
//! A value can be unremarkable globally yet wrong *for its moment* — a normal
//! daytime traffic level appearing at 3am, a weekday volume on a Sunday. Given a
//! declared period `p` (rows are treated as an ordered time series), each point
//! is compared only against its own phase `row mod p` — its seasonal peers —
//! using the same robust modified z-score as the point detector.
//!
//! Seasonality is never guessed: with no period configured the detector reports
//! honest absence rather than inventing one.

use crate::config::DetectConfig;
use crate::{robustz, Detector, Report, ScanContext};
use ax_core::finding::Handle;
use ax_core::{AnomalyClass, Column, Finding, RecordSet};

#[derive(Debug, Default, Clone)]
pub struct SeasonalDetector;

impl SeasonalDetector {
    /// Scans one column's phases, returning whether any phase had enough data to
    /// be assessed.
    fn scan_column(&self, col: &Column, cfg: &DetectConfig, out: &mut Report) -> bool {
        let p = cfg.ctx_period;
        let mut assessed = false;
        for phase in 0..p {
            // Collect (row, value) for this phase, in row order.
            let members: Vec<(usize, f64)> = col
                .cells
                .iter()
                .enumerate()
                .skip(phase)
                .step_by(p)
                .filter_map(|(row, cell)| cell.as_f64().filter(|v| v.is_finite()).map(|v| (row, v)))
                .collect();
            if members.len() < cfg.ctx_min_per_phase {
                continue;
            }
            let values: Vec<f64> = members.iter().map(|(_, v)| *v).collect();
            let Some((center, scale, k)) = robustz::center_scale(&values) else {
                continue;
            };
            assessed = true;
            for (row, v) in members {
                let modz = robustz::score(v, center, scale, k);
                if modz <= cfg.ctx_threshold {
                    continue;
                }
                out.push(Finding::new(
                    self.id(),
                    AnomalyClass::Contextual,
                    Handle::Cell {
                        column: col.name.clone(),
                        row,
                    },
                    robustz::confidence(modz, cfg.ctx_threshold),
                    modz,
                    format!(
                        "{} = {v:.6} at row {row} (phase {phase}/{p}): modified z-score {modz:.3} within its seasonal subseries exceeds {:.3}",
                        col.name, cfg.ctx_threshold
                    ),
                ));
            }
        }
        assessed
    }
}

impl Detector for SeasonalDetector {
    fn id(&self) -> &'static str {
        "ctx.seasonal"
    }
    fn class(&self) -> AnomalyClass {
        AnomalyClass::Contextual
    }
    fn detect(&self, ctx: &ScanContext, cfg: &DetectConfig, out: &mut Report) {
        if cfg.ctx_period < 2 {
            out.mark_absent(
                self.id(),
                "contextual detection needs a declared period ≥ 2 (pass --period N)",
            );
            return;
        }
        let assessed = scan_all(self, ctx.current, cfg, out);
        if !assessed {
            out.mark_absent(
                self.id(),
                format!(
                    "no numeric column has ≥ {} values in any phase of period {}",
                    cfg.ctx_min_per_phase, cfg.ctx_period
                ),
            );
        }
    }
}

/// Scans every numeric column, returning whether any phase anywhere was
/// assessed (so the caller can report honest absence otherwise).
fn scan_all(det: &SeasonalDetector, rs: &RecordSet, cfg: &DetectConfig, out: &mut Report) -> bool {
    let mut assessed = false;
    for col in &rs.columns {
        if col.ty.is_numeric() {
            assessed |= det.scan_column(col, cfg, out);
        }
    }
    assessed
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::Value;

    fn weekly(cfg_period: usize) -> DetectConfig {
        DetectConfig {
            ctx_period: cfg_period,
            ..DetectConfig::default()
        }
    }

    fn col_corpus(values: &[f64]) -> RecordSet {
        RecordSet::new(
            "-",
            "t",
            vec![Column::new(
                "v",
                values.iter().map(|&x| Value::Float(x)).collect(),
            )],
        )
    }

    /// 5 cycles of period 7; phase φ sits near level φ·10 with small per-cycle
    /// wobble (so each phase has positive spread).
    fn seasonal_series() -> Vec<f64> {
        (0..35)
            .map(|i| (i % 7) as f64 * 10.0 + (i / 7) as f64 * 0.3)
            .collect()
    }

    fn run(rs: &RecordSet, cfg: &DetectConfig) -> Report {
        let mut out = Report::new();
        SeasonalDetector.detect(&ScanContext::single(rs), cfg, &mut out);
        out
    }

    #[test]
    fn absent_without_a_period() {
        let report = run(&col_corpus(&seasonal_series()), &DetectConfig::default());
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
        assert_eq!(report.absent[0].detector, "ctx.seasonal");
    }

    #[test]
    fn clean_seasonal_series_has_no_findings() {
        let report = run(&col_corpus(&seasonal_series()), &weekly(7));
        assert!(
            report.findings.is_empty(),
            "tidy seasonal data has no contextual outlier"
        );
        assert!(report.absent.is_empty(), "it ran; not absent");
    }

    #[test]
    fn value_anomalous_only_in_context_is_flagged() {
        let mut s = seasonal_series();
        // row 14 is phase 0 (normally ≈0); set it to 50 — a perfectly ordinary
        // value for phase 5, but a glaring outlier *for phase 0*.
        s[14] = 50.0;
        let report = run(&col_corpus(&s), &weekly(7));
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            report.findings[0].handle,
            Handle::Cell { row: 14, .. }
        ));
        assert_eq!(report.findings[0].class, AnomalyClass::Contextual);
    }

    #[test]
    fn absent_when_no_phase_has_enough_data() {
        // period 50 over only 35 rows → every phase has < ctx_min_per_phase.
        let report = run(&col_corpus(&seasonal_series()), &weekly(50));
        assert!(report.findings.is_empty());
        assert_eq!(report.absent.len(), 1);
        assert!(report.absent[0].reason.contains("phase"));
    }

    #[test]
    fn period_two_is_assessed_not_absent() {
        // period 2 is the smallest valid season; it must run, not be treated as
        // "no period". Pins the `ctx_period < 2` guard against <= / == mutations.
        let v: Vec<f64> = (0..12)
            .map(|i| if i % 2 == 0 { 10.0 } else { 20.0 } + (i / 2) as f64 * 0.1)
            .collect();
        let report = run(&col_corpus(&v), &weekly(2));
        assert!(report.absent.is_empty(), "period 2 must be assessed");
    }

    #[test]
    fn phase_with_exactly_min_members_is_assessed() {
        // 4 cycles of period 7 → exactly ctx_min_per_phase (4) values per phase.
        // An injected phase-0 anomaly must still be flagged (pins the
        // `members.len() < min` boundary against <= / ==).
        let mut v: Vec<f64> = (0..28)
            .map(|i| (i % 7) as f64 * 10.0 + (i / 7) as f64 * 0.3)
            .collect();
        v[7] = 55.0; // phase 0, cycle 1: anomalous for phase 0
        let report = run(&col_corpus(&v), &weekly(7));
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            report.findings[0].handle,
            Handle::Cell { row: 7, .. }
        ));
    }

    #[test]
    fn deterministic_across_runs() {
        let mut s = seasonal_series();
        s[14] = 50.0;
        let rs = col_corpus(&s);
        let a = run(&rs, &weekly(7));
        let b = run(&rs, &weekly(7));
        assert_eq!(
            serde_json::to_string(&a.findings).unwrap(),
            serde_json::to_string(&b.findings).unwrap()
        );
    }
}
