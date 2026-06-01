//! Detector configuration and the config-version fingerprint.
//!
//! The fingerprint goes into the envelope: *same input + same fingerprint ⇒
//! same bytes*. Any change to a threshold that could change output also changes
//! the fingerprint, so an agent can tell "the data changed" from "the tool's
//! configuration changed."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectConfig {
    /// Modified z-score threshold for the point detector (Iglewicz–Hoaglin
    /// default is 3.5).
    pub point_threshold: f64,
    /// Minimum count of finite numeric values a column needs before the point
    /// detector will assess it. Below this, statistics are unreliable.
    pub point_min_n: usize,
    /// Optional false-discovery-rate (FDR) level for the point detector. When
    /// set, the per-cell modified-z threshold is replaced by Benjamini–Hochberg
    /// control at this level, applied within each column: a cell is flagged only
    /// if its two-sided p-value survives BH, bounding the expected proportion of
    /// false flags at `q`. `None` keeps the fixed `point_threshold` behavior.
    pub point_fdr_q: Option<f64>,

    /// Significance level for the KS and chi-square drift tests. A column is
    /// flagged when the test's p-value falls below this.
    pub dist_alpha: f64,
    /// Population Stability Index threshold; PSI above this signals drift
    /// (0.1 ≈ moderate, 0.2 ≈ significant by convention).
    pub psi_threshold: f64,
    /// Number of (baseline-quantile) bins used for PSI.
    pub psi_bins: usize,
    /// Minimum sample size (per side) before a distributional test runs.
    pub dist_min_n: usize,

    /// Null fraction above which the structural detector flags a column.
    pub struct_null_rate: f64,

    /// Significance level for the Mahalanobis multivariate test (per row).
    /// Smaller than the per-column α because every row is tested.
    pub mv_alpha: f64,
    /// Minimum number of complete (no-missing) rows before the multivariate
    /// detector will estimate a covariance and run.
    pub mv_min_n: usize,
    /// Relative ridge added to the covariance diagonal for numerical stability
    /// (handles collinear / zero-variance columns). Scaled by the mean variance.
    pub mv_ridge: f64,

    /// Seasonal period for the contextual detector. `0` (or `1`) disables it —
    /// seasonality is never guessed, so without a declared period the detector
    /// reports honest absence.
    pub ctx_period: usize,
    /// Modified z-score threshold within a seasonal subseries.
    pub ctx_threshold: f64,
    /// Minimum finite values a phase needs before it is assessed.
    pub ctx_min_per_phase: usize,

    /// Minimum length of an ordered numeric column before the collective
    /// (change-point) detector will run.
    pub coll_min_n: usize,
    /// Standardized mean-shift threshold for the collective detector. Set
    /// conservatively because the change point is chosen by maximization.
    pub coll_threshold: f64,

    /// Column to assess for metronomic cadence (interpreted as event times).
    /// `None` disables the cadence detector — which timestamps mean "time" is
    /// never guessed, so without this it reports honest absence.
    pub cadence_column: Option<String>,
    /// Coefficient-of-variation threshold below which inter-arrival intervals
    /// are flagged as suspiciously regular (automated).
    pub cad_max_cv: f64,
    /// Minimum number of intervals before cadence is assessed.
    pub cad_min_n: usize,
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            point_threshold: 3.5,
            point_min_n: 8,
            point_fdr_q: None,
            dist_alpha: 0.05,
            psi_threshold: 0.2,
            psi_bins: 10,
            dist_min_n: 20,
            struct_null_rate: 0.5,
            mv_alpha: 0.001,
            mv_min_n: 20,
            mv_ridge: 1e-9,
            ctx_period: 0,
            ctx_threshold: 3.5,
            ctx_min_per_phase: 4,
            coll_min_n: 20,
            coll_threshold: 5.0,
            cadence_column: None,
            cad_max_cv: 0.05,
            cad_min_n: 20,
        }
    }
}

impl DetectConfig {
    /// A stable, human-legible fingerprint of the settings that affect output.
    /// Deterministic: no wall-clock, no environment.
    pub fn version(&self) -> String {
        format!(
            "anomalyx-cfg/6;pt={:.4};ptn={};pfdr={};da={:.4};psi={:.4};psib={};dmn={};snr={:.4};mva={:.5};mvn={};mvr={:e};cxp={};cxt={:.4};cxm={};cln={};clt={:.4};cdc={};cdcv={:.4};cdn={}",
            self.point_threshold,
            self.point_min_n,
            self.point_fdr_q.map(|q| format!("{q:.4}")).unwrap_or_default(),
            self.dist_alpha,
            self.psi_threshold,
            self.psi_bins,
            self.dist_min_n,
            self.struct_null_rate,
            self.mv_alpha,
            self.mv_min_n,
            self.mv_ridge,
            self.ctx_period,
            self.ctx_threshold,
            self.ctx_min_per_phase,
            self.coll_min_n,
            self.coll_threshold,
            self.cadence_column.as_deref().unwrap_or(""),
            self.cad_max_cv,
            self.cad_min_n,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_stable_and_reflects_changes() {
        let a = DetectConfig::default();
        let b = DetectConfig::default();
        assert_eq!(a.version(), b.version());

        let c = DetectConfig {
            point_threshold: 4.0,
            ..DetectConfig::default()
        };
        assert_ne!(a.version(), c.version());

        // Enabling FDR control changes the fingerprint (and the empty default
        // renders as no value, so `pfdr=;` for the off case).
        let f = DetectConfig {
            point_fdr_q: Some(0.05),
            ..DetectConfig::default()
        };
        assert_ne!(a.version(), f.version());
        assert!(a.version().contains(";pfdr=;"));
        assert!(f.version().contains(";pfdr=0.0500;"));
    }
}
