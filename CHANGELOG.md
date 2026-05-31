# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-31

Format explosion — anomalyx now normalizes ~30 formats spanning logs, security
telemetry, network captures, observability streams, spreadsheets, and data-lake
files, all behind the same record-model boundary and detector taxonomy.

### Added

- **Logs & observability** parsers: `logfmt`, web access logs (Combined/Common),
  `syslog` (RFC 3164/5424), `systemd journal` (`journalctl -o json`),
  `Prometheus`/OpenMetrics, and `OpenTelemetry` (OTLP/JSON traces).
- **Security telemetry** parsers: `CEF`/`LEEF`, Linux `auditd`, `EVTX` (Windows
  Event Log), Suricata/Zeek `EVE` JSON, `osquery` results, and AWS `CloudTrail`.
- **Network** parsers: `PCAP`/`PCAPNG` (beaconing/C2 via `cadence`), `NetFlow`/
  IPFIX (nfdump CSV), AWS `VPC Flow Logs`, and DNS query logs (DGA/exfil via
  `point` on query-name entropy/length).
- **Structured-data** parsers: `YAML`, `TOML`/`INI`, and `XML`
  (Nessus/OpenVAS/SOAP).
- **Columnar, data-lake & database** parsers: `Avro`, `ORC`, Excel/`ODS`
  (`xlsx`/`xls`/`xlsb`), and `SQLite` — joining the existing Parquet/Arrow.
- Several parsers **compute detection features** (DNS name entropy/length, flow
  `duration`, span durations, normalized epoch timestamps) and rename source
  fields to a canonical schema.
- Binary/heavyweight parsers sit behind **default-on feature flags**
  (`evtx`, `pcap`, `xlsx`, `sqlite`, `datalake`, `polars`), so
  `--no-default-features` is a lean text-only normalizer.

### Notes

- 32 parser plugins total; each ships its own property/exact tests and passes
  the workspace-wide 0-surviving-mutant gate.

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

[Unreleased]: https://github.com/copyleftdev/anomalyx/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/copyleftdev/anomalyx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/copyleftdev/anomalyx/releases/tag/v0.1.0
