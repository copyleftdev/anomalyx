# anomalyx

[![crates.io](https://img.shields.io/crates/v/anomalyx.svg)](https://crates.io/crates/anomalyx)
[![CI](https://github.com/copyleftdev/anomalyx/actions/workflows/ci.yml/badge.svg)](https://github.com/copyleftdev/anomalyx/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Contract-first anomaly detection over arbitrary corpora — a CLI built on the
thesis of [*AI Tools Need Contracts, Not Prompts*][article]: **the executable is
the contract.**

anomalyx meets your data where it already lives. Point it at **~30 formats** —
logs, security telemetry, packet captures, flow records, observability streams,
spreadsheets, and data-lake files — and it normalizes each into one typed record
model, runs a battery of deterministic anomaly detectors, and returns a dense,
versioned, machine-readable envelope an agent can trust — not pretty text it has
to scrape.

[article]: https://dev.to/copyleftdev/ai-tools-need-contracts-not-prompts-5ca3

## The four-verb contract

```text
anomalyx describe                    # protocol metadata: what this is, formats, detectors
anomalyx schema                      # JSON Schema of scan output (validate, don't guess)
anomalyx scan [--baseline B] [PATH]  # normalize + detect → dense tq1 envelope
anomalyx explain <HANDLE> [PATH]     # resolve a finding handle back to its evidence
```

With `--baseline B`, the current corpus is compared against `B`: distributional
drift and schema-diff detectors activate. Without it they report honest absence
("no baseline provided"), and only single-corpus detectors run.

With `--period N`, rows are treated as an ordered time series and the contextual
(seasonal-subseries) detector compares each point to its phase peers. Without a
period it reports honest absence — seasonality is never guessed.

With `--cadence COL`, column `COL` is read as event times and assessed for
metronomic (automated) regularity. Without it the cadence detector is absent —
which column means "time" is never guessed.

With `--columns C,..` (or its complement `--exclude C,..`) detection is scoped to
a chosen set of columns — the answer to identifier noise on wide corpora (e.g.
`journalctl -o json | anomalyx scan --exclude JOB_ID,_PID,__REALTIME_TIMESTAMP`).
The scope is explicit, never a heuristic guess; an unknown column name is a hard
error so a typo can't silently scan nothing. See [scan modes](docs/src/modes.md).

Exit codes are part of the contract: **`0`** clean · **`1`** anomalies found ·
**`2`** tool error.

```console
$ printf 'id,amount\n1,10\n2,11\n3,9\n4,10\n5,12\n6,11\n7,10\n8,9\n9,9999\n' | anomalyx scan
{"protocol":"anomalyx/tq1",...,"rows":[[0,1,2,1.0,3,4544.43,4]],...,"exit":1}

$ ... | anomalyx explain cell:amount:8
{"evidence":{"kind":"cell","column":"amount","row":8,"value":{"t":"int","v":9999}}, "findings":[...]}
```

## Design commitments (straight from the article)

- **Typed dense output** — a versioned `tq1` envelope with a dictionary-pinned
  string table and dense finding rows. Field changes are API changes.
- **Determinism is UX** — order-independent (Kahan/Neumaier) reductions, no
  wall-clock in the measurement path, a config-version fingerprint. Same input +
  same fingerprint ⇒ byte-identical output.
- **Honest absence** — a detector that can't run is recorded in `absent` with a
  reason; a `Null` never silently becomes `0.0`; an unresolved handle fails
  cleanly with exit `2`.
- **Handle-based evidence** — `scan` stays compact; `explain` drills in.

## Formats

**32 built-in parsers** across five domains — each an independent plugin, each
lowered to the same typed `RecordSet`:

- **Tabular & structured** — CSV, TSV, NDJSON, JSON, YAML, TOML/INI, XML
- **Columnar, data-lake & databases** — Parquet, Arrow IPC, Avro, ORC,
  Excel/ODS, SQLite
- **Logs & observability** — logfmt, web access logs, syslog (RFC 3164/5424),
  systemd journal, Prometheus/OpenMetrics, OpenTelemetry (OTLP)
- **Security telemetry** — Zeek, CEF/LEEF, auditd, EVTX (Windows Event Log),
  Suricata/Zeek EVE, osquery, AWS CloudTrail
- **Network** — PCAP/PCAPNG, NetFlow/IPFIX (nfdump CSV), AWS VPC Flow Logs,
  DNS query logs

Several parsers compute the features the detectors want — DNS query-name entropy
& length, flow `duration`, span durations, normalized timestamps — and rename
cryptic source fields to a canonical schema. So the same taxonomy lights up
across domains: **beaconing/C2** via `cadence` on PCAP inter-arrival times,
**DGA/exfil** via `point` on DNS name entropy, **config drift** via
`struct.schema` on YAML/TOML, **exfil** via `mv.mahalanobis` on NetFlow
(bytes, packets, duration), **alert-type drift** via `dist.chi2` on EVE/CEF.

Resolution is by extension first, then deterministic content sniff (binary magic
before text signatures); an unrecognized stream is an explicit error, never a
guess. Binary/heavyweight parsers sit behind default-on feature flags, so
`--no-default-features` yields a lean, text-only normalizer. Full table:
[docs › Input & normalization](https://copyleftdev.github.io/anomalyx/formats.html).

## Architecture

```
crates/
  ax-core       contract types: RecordSet, anomaly taxonomy, tq1 envelope,
                handles, deterministic reductions  (no heavy deps — the contract
                stays engine-independent and the mutation gate stays fast)
  ax-normalize  any input format → RecordSet  (32 parser plugins — text via a
                lean deterministic reader, binary/library-backed formats behind
                default-on feature flags — all lowered to the same RecordSet so
                detectors never see a library type. See "Formats" below)
  ax-detect     Detector trait + registry; detection math assembled from
                statrs, not reinvented
  anomalyx      the four-verb CLI surface (the installable crate / binary)
```

Install: `cargo install anomalyx`.

## Examples

Worked examples of *consuming the `tq1` contract* on real data — they parse the
dense JSON envelope and map handles back to time, never scrape pretty text. See
[`examples/`](examples/README.md) for details and how to run each.

- [`stock_anomalies.py`](examples/README.md#stock_anomaliespy) — anomalous
  trading days (and distributional drift vs. another ticker) from Yahoo Finance.
- [`journal_anomalies.py`](examples/README.md#journal_anomaliespy) — anomalies in
  the systemd journal, piped from `journalctl -o json`.
- [`polymarket_anomalies.py`](examples/README.md#polymarket_anomaliespy) —
  information shocks and odds regime shifts in a Polymarket prediction market.
- [`synergy_market.py`](examples/README.md#synergy_marketpy) — anomalyx paired
  with [`agent-calc`](https://github.com/copyleftdev/agent-calc): anomalyx
  *finds* the anomalies, the exact-math kernel *proves* what they mean (tail
  probability, a t-test across the regime break, exact correlations).

## Anomaly taxonomy

Seven classes, so an agent reasons about the *kind* of deviation:

| Class | Meaning | Status |
|---|---|---|
| `point` | value far from its column's distribution (modified z / MAD) | ✅ `point.modz` |
| `distributional` | the distribution shifted vs. a baseline (KS / PSI / χ²) | ✅ `dist.ks`, `dist.psi`, `dist.chi2` |
| `structural` | schema / type / null-rate violation, baseline schema-diff | ✅ `struct.schema` |
| `contextual` | anomalous only in context (seasonal subseries) | ✅ `ctx.seasonal` |
| `collective` | a subsequence is jointly anomalous (level shift) | ✅ `coll.cusum` |
| `multivariate` | a row isolated in feature space — breaks the joint structure | ✅ `mv.mahalanobis` |
| `cadence` | suspiciously *regular* timing (automation) | ✅ `cad.regularity` |

## Build vs. assemble

Detection *math* is largely solved and is reused where it fits: `statrs`
(distributions, χ² / KS p-values), `polars` (normalization). Where the
determinism gate makes an off-the-shelf algorithm a liability — e.g. an
isolation forest's RNG fights byte-reproducibility — anomalyx instead uses a
fully deterministic method (the multivariate detector is Mahalanobis distance
over a self-contained Cholesky solve, no RNG). What anomalyx *invents* is the
part no crate provides: the executable contract — the envelope, the taxonomy +
explainable detector registry, cross-corpus drift orchestration, and the
determinism guarantees.

## Validation against NIST

Beyond unit/property tests, the math core is checked against the **NIST
Statistical Reference Datasets (StRD)** — the canonical, certified-to-15-digits
truth for univariate statistics. The datasets are vendored under
`crates/ax-validate/data/strd/` (offline, reproducible) and scored by NIST's own
log-relative-error (number of correct significant digits):

- `det::mean` reproduces every certified mean to **≥15 digits**; `det::std_dev`
  to **≥13** on well-conditioned data.
- On the `NumAcc3`/`NumAcc4` precision torture tests (mean ≈ 1e6–1e7, spread 0.1)
  the compensated two-pass holds **8–9 correct digits** where the textbook
  one-pass variance gets **zero** — a checked demonstration that the determinism
  design is load-bearing, not decorative.

Stress tests add ground-truth anomaly recovery (planted outliers flagged with
no false positives/negatives), order-independence on real 5000-point data, and
byte-identical reproducibility on a 40k-row scan.

## The strong gates

Two load-bearing test gates, run by `scripts/gates.sh`:

1. **Property-based testing** (`proptest`) — pins invariants across all inputs:
   shift/scale/permutation invariance and determinism for the point detector,
   round-trips and idempotence for the contract types.
2. **Mutation testing** (`cargo-mutants`) — proves those tests have teeth. The
   gate is **0 surviving mutants** on `src/`. Provably-equivalent mutants are
   documented individually in `.cargo/mutants.toml`, never blanket-suppressed.

```console
$ ./scripts/gates.sh          # fmt · clippy -D warnings · tests · mutants==0
```

Current status: workspace builds clean, `clippy -D warnings` passes, all tests
green, and every crate passes the 0-survivor mutation gate. CI
(`.github/workflows/ci.yml`) runs fmt/clippy/test on every push; the mutation
gate runs locally via `./scripts/gates.sh` (it's too minutes-expensive for CI).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work
shall be dual licensed as above, without any additional terms or conditions.
