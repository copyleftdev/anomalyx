# anomalyx

[![crates.io](https://img.shields.io/crates/v/anomalyx.svg)](https://crates.io/crates/anomalyx)
[![CI](https://github.com/copyleftdev/anomalyx/actions/workflows/ci.yml/badge.svg)](https://github.com/copyleftdev/anomalyx/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Contract-first anomaly detection over arbitrary corpora — a CLI built on the
thesis of [*AI Tools Need Contracts, Not Prompts*][article]: **the executable is
the contract.** Point a normalizer at any supported format, run a battery of
typed anomaly detectors, and get back a dense, versioned, machine-readable
envelope an agent can trust — not pretty text it has to scrape.

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

## Architecture

```
crates/
  ax-core       contract types: RecordSet, anomaly taxonomy, tq1 envelope,
                handles, deterministic reductions  (no heavy deps — the contract
                stays engine-independent and the mutation gate stays fast)
  ax-normalize  any input format → RecordSet  (CSV/TSV/NDJSON/JSON via a lean
                deterministic reader; Parquet/Arrow IPC via the Polars backbone,
                behind the default-on `polars` feature — all lowered to the same
                RecordSet so detectors never see a Polars type)
  ax-detect     Detector trait + registry; detection math assembled from
                statrs, not reinvented
  anomalyx      the four-verb CLI surface (the installable crate / binary)
```

Install: `cargo install anomalyx`.

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
