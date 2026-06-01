# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-05-31

### Fixed

- **SQLite: WAL-mode databases now read.** The parser loads a database from its
  main-file byte image via SQLite's read-only deserialize. A database in WAL
  journal mode carries read-version `2` in its file header (byte 19), and SQLite
  refuses to open such an image read-only without the `-wal` companion (which
  never travels in a byte stream) — failing with `unable to open database file`
  (`SQLITE_CANTOPEN`). Since the main image of a checkpointed WAL database is a
  complete, valid database, the parser now reinterprets it as legacy
  (read-version `1`) on a private copy and reads its checkpointed state. This
  unblocks the common case: most production `.db` files (browsers, peewee, and
  countless apps) default to WAL. Found by dogfooding real on-disk databases.

## [0.4.0] - 2026-05-31

### Added

- **`scan` / `explain` gain `--cad-max-cv F`** — the maximum inter-arrival
  coefficient of variation below which `cad.regularity` flags a column as
  metronomic (automated) timing. Defaults to `0.05` (unchanged behavior). Raise
  it to catch *jittered* beacons: a C2 channel with ~10% timing jitter
  (CV ≈ 0.10) slips past the default but is caught at `--cad-max-cv 0.15`.
- The threshold is part of the **`config_version` fingerprint** (`cdcv=`), so
  overriding it is a visible, versioned change in the envelope — not a silent
  knob. Same input + same `config_version` still yields byte-identical output.

### Notes

- Validated against a deterministic jitter sweep: at the default `0.05` the
  detector fires up to CV ≈ 0.0494 and goes quiet at ≈ 0.0504 (it uses the
  sample/Bessel-corrected standard deviation); raising the threshold shifts that
  boundary exactly as expected.

## [0.3.0] - 2026-05-31

Column scoping — focus detection on the columns that matter in a wide corpus,
deterministically and without guessing.

### Added

- `scan` / `explain` gain **`--columns C,..`** (analyze only these columns) and
  **`--exclude C,..`** (analyze every column except these). The two are mutually
  exclusive. Projection is applied before detection and to the baseline as well,
  so drift comparison stays consistent.
- Column scoping is **explicit, never heuristic.** anomalyx will not guess which
  columns are "interesting" — a silent auto-skip would itself be a guess, and
  would wrongly drop exactly the near-unique numeric measurements the marquee
  detectors rely on (packet `durationNanos`, span durations, latencies). You name
  the scope; the result stays deterministic and reproducible.
- An unknown column name in `--columns`/`--exclude` on the primary corpus is a
  hard error (exit `2`) — a typo can never silently scope a scan down to nothing
  and read as "clean". The baseline is projected leniently (it is a different
  corpus and need not carry every scoped column).

### Notes

- This directly tames wide, identifier-heavy corpora. On a real 20k-entry
  `journalctl -o json` capture, `scan` emits ~10k mostly-noise `point` findings
  across journald's many ID/counter/timestamp fields; `scan --exclude` of those
  fields (or `--columns` of the meaningful ones) collapses that to a couple
  hundred focused findings without touching detector configuration.
- New `RecordSet::select` / `RecordSet::without` projection primitives in
  `ax-core`. No envelope or `config_version` change — column scope is an
  input-side projection, so the determinism contract is unchanged.

## [0.2.2] - 2026-05-31

### Fixed

- A plain-text stream that merely *starts with* `[` or `{` (e.g. an Apache
  `error_log`) was grabbed by the JSON parser's cheap content sniff and then
  failed with a misleading `failed to parse json input`. Now a parse failure
  under a **weak** (`TEXT`/`FALLBACK`) content guess is reported honestly as
  `UnknownFormat` — "I don't recognize this" rather than "your JSON is broken".
  A format identified confidently (by file extension, or a `MAGIC`/`STRONG`
  signature) still surfaces a genuine malformed-file parse error as before.

## [0.2.1] - 2026-05-31

### Fixed

- `describe` advertised only the original six `input_formats`
  (`csv`/`tsv`/`ndjson`/`json`/`parquet`/`arrow`) — a stale literal that never
  tracked the 26 parsers added since. It now derives the list from the live
  parser registry, so it reflects exactly what the build reads (all 32 with
  default features; fewer under `--no-default-features`). A guard test asserts
  `describe`'s formats equal the registry, so it can't drift again.

### Added

- `anomalyx --version` (`-V` / `version`) prints the crate version.

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

[Unreleased]: https://github.com/copyleftdev/anomalyx/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/copyleftdev/anomalyx/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/copyleftdev/anomalyx/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/copyleftdev/anomalyx/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/copyleftdev/anomalyx/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/copyleftdev/anomalyx/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/copyleftdev/anomalyx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/copyleftdev/anomalyx/releases/tag/v0.1.0
