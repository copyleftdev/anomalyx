# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-30

Initial release — a contract-first anomaly-detection CLI over arbitrary corpora.

### Added

- **Contract surface** (`anomalyx`): the four discoverable verbs `describe`,
  `schema`, `scan`, `explain`; a dense, versioned `tq1` JSON envelope with a
  dictionary-pinned string table and stable evidence handles; committed exit
  codes (`0` clean / `1` anomalies / `2` error); honest absence for detectors
  that cannot run.
- **Normalization** (`ax-normalize`): CSV, TSV, NDJSON and JSON via a lean
  deterministic reader; Parquet and Arrow IPC via the Polars backbone (behind
  the default-on `polars` feature). Every format is lowered to one
  engine-independent `RecordSet`, so detectors never see a Polars type.
- **Detectors** (`ax-detect`) — nine across the full seven-class taxonomy:
  - `point.modz` — Iglewicz–Hoaglin modified z-score (robust MAD).
  - `dist.ks` — two-sample Kolmogorov–Smirnov drift.
  - `dist.psi` — Population Stability Index over baseline-quantile bins.
  - `dist.chi2` — chi-square over category frequencies (surfaces new categories).
  - `struct.schema` — mixed-type and high-null-rate columns; added / dropped /
    type-changed columns against a baseline.
  - `mv.mahalanobis` — multivariate Mahalanobis distance (own deterministic
    Cholesky solve; chi-square p-value).
  - `ctx.seasonal` — contextual seasonal-subseries modified z-score (`--period`).
  - `coll.cusum` — collective CUSUM level-shift detection.
  - `cad.regularity` — metronomic-cadence (inter-arrival CV) detection
    (`--cadence`).
- **Modes**: single-corpus scan; `--baseline B` for distributional drift and
  schema diff; `--period N` for seasonal/contextual; `--cadence COL` for timing.
- **Determinism**: order-independent (Neumaier-compensated) reductions, no RNG
  or wall-clock in the measurement path, and a config-version fingerprint —
  same input + same fingerprint yields byte-identical output.
- **Validation** (`ax-validate`): the math core is checked against the NIST
  Statistical Reference Datasets (certified to 15 digits), plus stress tests for
  ground-truth anomaly recovery and reproducibility at scale.
- **Quality gates**: property-based tests (`proptest`) and a `cargo-mutants`
  0-surviving-mutant gate across the workspace; GitHub Actions CI runs the same
  gates on every push.
- Dual-licensed under MIT OR Apache-2.0.

[Unreleased]: https://github.com/copyleftdev/anomalyx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/copyleftdev/anomalyx/releases/tag/v0.1.0
