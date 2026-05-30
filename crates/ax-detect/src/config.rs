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
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            point_threshold: 3.5,
            point_min_n: 8,
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
        }
    }
}

impl DetectConfig {
    /// A stable, human-legible fingerprint of the settings that affect output.
    /// Deterministic: no wall-clock, no environment.
    pub fn version(&self) -> String {
        format!(
            "anomalyx-cfg/4;pt={:.4};ptn={};da={:.4};psi={:.4};psib={};dmn={};snr={:.4};mva={:.5};mvn={};mvr={:e};cxp={};cxt={:.4};cxm={};cln={};clt={:.4}",
            self.point_threshold,
            self.point_min_n,
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
    }
}
