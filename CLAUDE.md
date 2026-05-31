# anomalyx — project guide for Claude Code

Contract-first anomaly detection over arbitrary corpora. The thesis (from *AI
Tools Need Contracts, Not Prompts*): **the executable is the contract.** Output
is a dense, versioned `tq1` JSON envelope an agent can trust — never pretty text.

## Non-negotiables (these override convenience)

1. **Determinism is a hard requirement.** No wall-clock, no RNG, no environment
   reads in the measurement path. All numeric reductions go through
   `ax_core::det` (order-independent, Neumaier-compensated). Same input + same
   `config_version` ⇒ **byte-identical** output. If you reach for randomness,
   you're solving it wrong — find the deterministic method (e.g. Mahalanobis,
   not isolation forest).
2. **Honest absence.** A detector that can't run records an `Absence` with a
   reason; it never fabricates a clean result. A missing cell is `Value::Null`,
   never `0.0`. An unresolved `explain` handle fails with exit code `2`.
3. **The `tq1` envelope is an API.** Changing a field, the dense row layout, an
   exit code, or a handle form is a breaking change: bump `envelope::PROTOCOL`,
   update `anomalyx schema`, and update the contract tests. Don't weaken it
   casually.
4. **The strong gates are the definition of done.** Property-based tests
   (`proptest`) **and** mutation testing (`cargo-mutants`) with **zero surviving
   (missed) mutants**. Timeouts are acceptable (loop-bound hangs = detected).
   Run `./scripts/gates.sh` before every push; CI enforces it.
5. **Equivalent mutants are documented, never blanket-suppressed.** If a mutant
   truly cannot change observable behavior, prove why in a comment and add a
   specific entry to `.cargo/mutants.toml`. Prefer killing it with a test or a
   small refactor first.
6. **Exit codes are committed:** `0` clean · `1` anomalies found · `2` error.

## Architecture

5-crate workspace. The contract is engine-independent so the heavy machinery can
change without the output shape moving.

- `ax-core` (pkg `anomalyx-core`) — contract types: `RecordSet`, the 7-class
  anomaly taxonomy, the `tq1` envelope, handles, deterministic reductions
  (`det`). **No heavy deps** — keep it small so the mutation gate stays fast.
- `ax-normalize` (pkg `anomalyx-normalize`) — any format → `RecordSet` via a
  **parser plugin registry**. Polars (Parquet/Arrow) lives only here, behind the
  default-on `polars` feature.
- `ax-detect` (pkg `anomalyx-detect`) — the `Detector` trait + `Registry`; the
  nine detectors. Math assembled from `statrs`, not reinvented.
- `anomalyx` — the four-verb CLI (`describe`/`schema`/`scan`/`explain`).
- `ax-validate` (`publish = false`) — NIST StRD validation + stress harness.

Note: crates.io packages are `anomalyx-*` but the in-source import names stay
`ax_core`/`ax_normalize`/`ax_detect` (Cargo dependency rename). Don't "fix" this.

## Adding things

- **A format**: new `crates/ax-normalize/src/parsers/<fmt>.rs` implementing
  `FormatParser` (id, extensions, content `sniff`, `parse`), then one
  `register(...)` line in `parsers/mod.rs::default_registry`. No central match.
  See the open `format` issues. The `@format-parser` agent / `add-format`
  workflow exist for this.
- **A detector**: implement `Detector` in `ax-detect` (`id`, `class`, `detect`
  over `ScanContext`), register in `Registry::default_set`, add any config to
  `DetectConfig` (and its `version()` fingerprint), emit findings with a stable
  `Handle` and a calibrated confidence. Honest absence when it can't run.
- Either way: PBT invariants + exact-value tests, then `cargo mutants` to 0
  survivors. The `@detector-author` and `@mutation-hardener` agents help.

## Commands

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo mutants -p <crate>          # gate: mutants.out/missed.txt must be empty
./scripts/gates.sh                # fmt + clippy + test + mutation, all of it
./scripts/publish.sh [--dry-run]  # crates.io publish, dependency order
mdbook build docs                 # the docs site (also auto-deployed by CI)
```

## Don't

- Add heavy dependencies to `ax-core`, or let Polars types escape `ax-normalize`.
- Introduce nondeterminism anywhere a result is computed.
- Weaken the `tq1` contract or a test assertion to make a gate pass.
- Commit/push or publish unless asked. Branch off `main` first.
