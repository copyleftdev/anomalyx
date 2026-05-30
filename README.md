# anomalyx

Contract-first anomaly detection over arbitrary corpora — a CLI built on the
thesis of [*AI Tools Need Contracts, Not Prompts*][article]: **the executable is
the contract.** Point a normalizer at any supported format, run a battery of
typed anomaly detectors, and get back a dense, versioned, machine-readable
envelope an agent can trust — not pretty text it has to scrape.

[article]: https://dev.to/copyleftdev/ai-tools-need-contracts-not-prompts-5ca3

## The four-verb contract

```text
anomalyx describe          # protocol metadata: what this is, formats, detectors
anomalyx schema            # JSON Schema of scan output (validate, don't guess)
anomalyx scan [PATH]       # normalize + detect → dense tq1 envelope
anomalyx explain <HANDLE>  # resolve a finding handle back to its evidence
```

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
  ax-normalize  any input format → RecordSet  (CSV/TSV/NDJSON/JSON today;
                Polars/Arrow backbone for Parquet/Arrow IPC lands behind the
                same boundary)
  ax-detect     Detector trait + registry; detection math assembled from
                statrs / (future) smartcore / augurs, not reinvented
  ax-cli        the four-verb surface
```

## Anomaly taxonomy

Seven classes, so an agent reasons about the *kind* of deviation:

| Class | Meaning | Status |
|---|---|---|
| `point` | value far from its column's distribution (modified z / MAD) | ✅ shipped |
| `distributional` | the distribution shifted vs. a baseline (KS / PSI / KL / χ²) | ⏳ next |
| `structural` | schema / type / cardinality violation | ⏳ next |
| `contextual` | anomalous only in context (seasonal) | ⏳ planned |
| `collective` | a subsequence/group is jointly anomalous (change-point) | ⏳ planned |
| `multivariate` | isolated in feature space (isolation forest / LOF / DBSCAN) | ⏳ planned |
| `cadence` | suspiciously regular timing | ⏳ planned |

## Build vs. assemble

Detection *math* is largely solved in the Rust ecosystem and is reused:
`statrs` (tests/distributions), `smartcore` (isolation forest, one-class SVM,
DBSCAN), `augurs`/`anomaly_detection` (seasonal), `polars` (normalization).
What anomalyx *invents* is the part no crate provides: the executable contract —
the envelope, the taxonomy + explainable detector registry, cross-corpus drift
orchestration, and the determinism guarantees.

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
green, and every crate passes the 0-survivor mutation gate.
