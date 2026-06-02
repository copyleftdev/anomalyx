# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-06-01

### Fixed

- **Timestamp columns are now recognized as sequences and skipped by the value
  detectors.** `Role::Sequence` required *strict* monotonicity, but real clock
  columns (journald's `__REALTIME_TIMESTAMP`/`__MONOTONIC_TIMESTAMP`, a pcap
  `timestamp`) tie or regress just often enough to fail it — so they were treated
  as measurements, and `coll.cusum` flagged their "level shift" (time advancing)
  and `point` their jumps. A `timestamp` / `ts` name token now classifies a
  column as `sequence`, kept deliberately narrow so `response_time`-style
  *measurements* (which you do want outliers on) are unaffected. Surfaced by the
  new journald example. No `config_version` change — a classifier refinement,
  like 1.0.1's `procid`.

### Examples

- **`examples/journal_anomalies.py`** — find anomalies in the systemd journal:
  point / structural / collective within one capture (e.g. CPU-usage spikes per
  unit), or distributional drift of `_SYSTEMD_UNIT` / `PRIORITY` between two
  windows (`--baseline-since`). Pipes journald JSON on stdin (so it sniffs as
  `journal`, not plain JSON) and maps findings back to timestamp / unit / message.
- **`examples/stock_anomalies.py`** — fetch a ticker's daily history from Yahoo
  Finance and find its anomalous trading days (point / multivariate / collective),
  or its distributional drift against another ticker (`--baseline`). A worked
  example of consuming the `tq1` envelope: it parses the dense JSON contract and
  maps each finding's handle back to a calendar date.
- Both live outside the Cargo workspace (they shell out to the installed
  binary), so they don't affect the build or gates.

## [1.1.0] - 2026-06-01

### Changed

- **Column roles now gate every value-distribution detector, not just `point`.**
  `ctx.seasonal`, `coll.cusum`, `dist.ks` / `dist.psi` / `dist.chi2`, and
  `mv.mahalanobis` now skip `identifier` and `sequence` columns (and exclude them
  from the Mahalanobis feature space). A seasonal subseries, level-shift, drift
  test, or joint distance over arbitrary ids or a monotonic ramp is noise, not
  signal — this fixes, e.g., `coll.cusum` flagging a shift in a syslog `procid`.
  A shared `Role::skips_value_detection()` keeps the rule in one place.
  (`struct.schema` stays role-agnostic — null-rate/schema-diff are meaningful for
  any column; `cad.regularity` only ever uses the explicit `--cadence` column.)
- This changes detector output when `column_roles = true`, so the
  `config_version` fingerprint is bumped (`anomalyx-cfg/9`). Envelope shape and
  `PROTOCOL` are unchanged; `--no-column-roles` restores the pre-roles behavior
  across all detectors.

### Testing

- Scoped the parser-robustness harness's magic-prefixed fuzz test to formats
  whose decode allocation anomalyx bounds (`sqlite`). The binary *container*
  decoders (`parquet`/`arrow`, `avro`, `orc`, `evtx`, `pcap`) delegate to crates
  that trust the file's internal length fields and can attempt a large
  allocation on adversarial input — a property of binary-format parsing, now
  **documented** rather than asserted (it surfaced as an intermittent CI OOM).
  Those parsers are still fuzzed with arbitrary bytes (rejected at the magic
  check).

## [1.0.1] - 2026-06-01

### Fixed

- **Syslog: the PRI-less file format now parses.** rsyslog/syslog-ng write
  `/var/log/syslog` without the `<PRI>` wire header (an ISO-8601 or BSD timestamp,
  then host and tag), but the parser's sniff required a `<PRI>` — so a real
  `/var/log/syslog` was misdetected as `ini` and collapsed to a single garbage
  row. It is now recognized (timestamp + host + app) and parses one row per line;
  `facility`/`severity` are present only when a `<PRI>` is. Found by dogfooding
  the host's real syslog (50k lines → `ini`/1 row, now → `syslog`/50k rows).
- **Column roles: `procid` is recognized as an identifier.** The syslog `procid`
  (process id) column was classed a `measurement`, so PIDs were flagged as point
  outliers (~18.5k noise findings on a 50k-line syslog). `procid` joins the
  identifier name set, so it is skipped like other ids (→ 1 finding).

## [1.0.0] - 2026-06-01

First stable release. No code changes from `0.9.0` — this commits the contract.

### Stable

- The **`tq1` contract is now stable**: the protocol id `anomalyx/tq1`, the exit
  codes (`0`/`1`/`2`), the dense finding-row layout, the handle forms
  (`column:`/`cell:`/`row:`/`range:`/`dist:`), the required envelope fields, and
  the severity ladder. Breaking any of these requires a major bump and a
  `PROTOCOL` change — they will not change quietly under `1.x`. See
  [the contract's Stability section](docs/src/contract.md).
- Continues to evolve *additively* under `1.x`: new detectors, formats, optional
  flags, and optional envelope fields. Output-affecting config changes move the
  `config_version` fingerprint; determinism (same input + same `config_version`
  ⇒ byte-identical output) is absolute. The golden-envelope tests guard all of
  this against accidental drift.

## [0.9.0] - 2026-06-01

### Added

- **`scan` / `explain` gain `--set KEY=VALUE`** (repeatable) — override any
  detector-config field by name (`--set point_threshold=4.0`, `--set
  dist_alpha=0.01`, `--set column_roles=false`, …). The settable keys and their
  defaults are exactly what `describe`'s `config` object lists. An unknown key,
  or a value that doesn't fit the field's type, is a hard error (exit `2`).
  Overrides flow into `config_version`, so a tuned run stays reproducible and
  self-describing — tuning is never silent. (The common knobs keep their
  dedicated flags: `--fdr`, `--cad-max-cv`, `--period`, `--cadence`.)
- Implemented as a JSON round-trip over the serialized `DetectConfig`, so every
  field is settable with no per-field code; no envelope/`PROTOCOL` change.

### Testing

- **Golden-envelope snapshot tests** (`anomalyx/tests/golden.rs`). Run the actual
  binary and pin its byte-exact stdout for `schema`, `describe`, and a
  representative `scan` envelope against committed goldens — so any accidental
  contract drift (renamed field, changed dense-row layout, shifted
  `config_version`, recalibrated confidence) fails CI as a visible diff.
  Regenerate intentional changes with `BLESS=1`.
- **Million-row scale test** (`ax-validate`): a 1,000,000-row scan must be
  byte-identical across runs *and* recover exactly the injected outliers —
  determinism and correctness verified at scale, not just on toy inputs.

## [0.8.0] - 2026-06-01

### Changed

- **Unified confidence calibration across all detectors.** Confidence was
  computed three incompatible ways (`1 − p` for the distributional/multivariate
  detectors, a logistic-over-threshold for point/contextual/collective/PSI, and a
  linear map for cadence), so a `0.9` meant different things depending on which
  detector produced it — and severity (and `--top` / `--min-severity`) couldn't
  rank across detectors. Now every detector routes through one shared function:
  confidence is a logistic of how far its statistic sits past its firing
  threshold, measured **relatively** so units cancel. At the threshold → `0.5`,
  rising toward `1.0`; a finding "2× past threshold" earns the same confidence on
  any detector. New `ax_detect::calibrate` module (`from_exceedance` /
  `from_undercut`); the duplicated `shift_confidence` / `psi_confidence` /
  `robustz::confidence` helpers are gone.
- This recalibrates every published confidence and severity. The `config_version`
  fingerprint is bumped (`anomalyx-cfg/8`) so the change is visible to agents.
  The envelope shape and `PROTOCOL` are unchanged.

### Testing

- **Parser robustness harness** (`ax-normalize/tests/robustness.rs`). Property
  tests assert that no parser panics, hangs, or over-allocates on arbitrary,
  magic-prefixed-garbage, or truncated byte streams — fed both through
  auto-detection and straight to every registered parser — and that
  normalization is deterministic over fuzz inputs. Untrusted-input hardening:
  a malformed file must fail cleanly, never crash.

## [0.7.0] - 2026-06-01

### Added

- **Column roles.** Every scanned column is classified into a role —
  `measurement` / `identifier` / `categorical` / `sequence` / `constant` — and the
  full map ships in the envelope's new `roles` array. The point detector skips
  `identifier` and `sequence` columns (a "large process-id" or a counter's
  endpoint is not an anomaly), attacking noise at the *detection* layer. On a real
  20k journald capture this cuts point findings from ~12,500 to ~240 while leaving
  genuine measurements (e.g. a parquet's heavily-skewed `DAYS_LOST`) untouched.
- **`--no-column-roles`** disables role-based skipping (roles are still reported).
  The setting is part of the `config_version` fingerprint (`cr=`).

### Design

- Identifiers are recognized by **name** (`*_id`, `uid`, `gid`, `pid`, `tid`,
  `session`, `uuid`, …) — the only reliable signal, since a process-id column is
  statistically indistinguishable from a discrete measurement. Cardinality is
  deliberately *not* used to call a numeric column categorical (a near-constant
  column with a few outliers has low cardinality yet is exactly what point
  detection should catch). Heuristic, but never silent: every role is in the
  envelope and the skipping is one flag away from off.
- New `ax_core::roles` module (`Role`, `ColumnRole`, `Column::role`); `roles`
  added to the envelope and `schema`. Additive; `PROTOCOL` unchanged.

## [0.6.0] - 2026-06-01

### Added

- **`scan` gains output scoping: `--top N` and `--min-severity S`.** `--top N`
  emits only the N most severe findings; `--min-severity S` emits only findings
  at or above `S` (`info`/`low`/`medium`/`high`/`critical`). This is the volume
  complement to `--fdr` — on a large corpus it shrinks the envelope dramatically
  (a real 127k-row parquet: ~3 MB → ~5.6 KB with `--top 25`) while keeping the
  full picture in `summary`.
- **Honest truncation.** `summary` (`total`, `by_class`, `max_severity`) and the
  **exit code** always describe everything *detected*, never the scoped view —
  so filtering can't make anomalies look absent or flip exit `1`→`0`. When
  findings are withheld, the envelope gains a `scope` block with the applied
  filter and `detected` / `emitted` / `dropped` counts; `rows` carries only the
  emitted subset. Absent when no scoping was applied (default output unchanged).

### Changed

- The envelope `summary.total` now reports the number of findings **detected**
  (unchanged when no output scoping is applied, since detected == emitted then).
  `rows.len()` equals `scope.emitted` when scoping is active. The `scope` field
  and updated `schema` are additive; `PROTOCOL` is unchanged.

## [0.5.0] - 2026-05-31

### Added

- **`scan` / `explain` gain `--fdr Q`** — false-discovery-rate control for the
  point detector via the **Benjamini–Hochberg** procedure, applied per column.
  When set, each cell's modified z-score is converted to a two-sided p-value and
  the fixed `point_threshold` is replaced by a multiplicity-aware cutoff that
  bounds the expected proportion of false flags at `Q` (e.g. `--fdr 0.05`).
  Opt-in: omitted, the detector behaves exactly as before. The level is part of
  the `config_version` fingerprint (`pfdr=`), so it is a versioned, reproducible
  choice.
- New `ax_detect::fdr` module: `two_sided_p` (normal-tail p-value via `erfc`) and
  `benjamini_hochberg` (deterministic step-up cutoff), each property/exact tested
  and mutation-gated.

### Notes

- **FDR is a *correctness* control, not a volume knob.** It replaces an arbitrary
  fixed cutoff with a principled error-rate guarantee and adapts to how many
  cells were tested (a noise column stops contributing chance flags; the same
  outlier can be significant in a small column yet not a large one). On genuinely
  heavy-tailed data it may flag **more** cells than the old fixed threshold — those
  cells really are significant at the chosen `Q`; the fixed cutoff was simply
  stringent in an uncalibrated way. To *cap* output volume, combine with column
  scoping (`--columns`/`--exclude`) and the planned severity / top-N output
  scoping.
- The p-value uses the consistent-σ standardized deviation `(x − center)/scale`
  (≈ `N(0, 1)` under the null), not `robustz`'s display-scaled modified z-score.

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

[Unreleased]: https://github.com/copyleftdev/anomalyx/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/copyleftdev/anomalyx/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/copyleftdev/anomalyx/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/copyleftdev/anomalyx/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/copyleftdev/anomalyx/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/copyleftdev/anomalyx/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/copyleftdev/anomalyx/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/copyleftdev/anomalyx/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/copyleftdev/anomalyx/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/copyleftdev/anomalyx/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/copyleftdev/anomalyx/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/copyleftdev/anomalyx/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/copyleftdev/anomalyx/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/copyleftdev/anomalyx/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/copyleftdev/anomalyx/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/copyleftdev/anomalyx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/copyleftdev/anomalyx/releases/tag/v0.1.0
