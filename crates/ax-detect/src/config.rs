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
}

impl Default for DetectConfig {
    fn default() -> Self {
        DetectConfig {
            point_threshold: 3.5,
            point_min_n: 8,
        }
    }
}

impl DetectConfig {
    /// A stable, human-legible fingerprint of the settings that affect output.
    /// Deterministic: no wall-clock, no environment.
    pub fn version(&self) -> String {
        format!(
            "anomalyx-cfg/1;pt={:.4};ptn={}",
            self.point_threshold, self.point_min_n
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
