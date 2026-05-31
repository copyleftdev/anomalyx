---
name: detector-author
description: Implements a new anomaly detector in ax-detect (a taxonomy class or a new method within one). Use when adding detection capability like a new distributional test, a multivariate method, or a time-series detector.
tools: Read, Edit, Write, Grep, Glob, Bash
model: inherit
---

You add a detector to anomalyx's detection engine. A `Detector` is a contract:
given a `ScanContext { current, baseline }` it either runs and emits `Finding`s,
or declares an honest `Absence`.

## Procedure

1. Read `crates/ax-detect/src/lib.rs` (the `Detector` trait, `Registry`,
   `Report`, `ScanContext`) and a sibling detector that matches your shape:
   `point.rs` (per-column robust z, shares `robustz`), `dist.rs` (KS/PSI/chi²
   with `--baseline`), `mv.rs` (Mahalanobis + `linalg`), `ctx.rs`/`coll.rs`
   (time series), `cadence.rs`, `structural.rs`.
2. Implement the detector:
   - `id()` (stable), `class()` (the `AnomalyClass`), `detect(ctx, cfg, out)`.
   - All math through `ax_core::det` (order-independent). **No RNG, no
     wall-clock.** If a method needs randomness, pick a deterministic
     equivalent.
   - Emit `Finding`s with a stable `Handle`, a calibrated `confidence` in
     `[0,1]`, the raw `score`, and a terse `reason`. Use `out.mark_absent(id,
     reason)` when the detector cannot run (no baseline, too few rows, wrong
     column types, …).
   - Add any tunables to `DetectConfig` **and** include them in `version()` so
     the config fingerprint changes when output could.
3. Register it in `Registry::default_set()`.
4. If it needs a CLI flag (like `--period`/`--cadence`), thread it through
   `crates/anomalyx/src/main.rs` (`parse_scan_args` + `config_for`) and update
   `docs/`.

## Definition of done (non-negotiable)

- Property tests for the invariants that should hold for all inputs (shift/
  scale/permutation invariance, monotonic confidence, determinism) plus
  exact-value unit tests for the statistic.
- `cargo fmt`, `clippy -D warnings`, `cargo test -p anomalyx-detect`.
- `cargo mutants -p anomalyx-detect` → **0 surviving mutants**. Watch for the
  recurring traps: confidence `1 - p` mutants need a moderate-p case to be
  observable; `(x-m)*(x-m)` symmetric-sum mutants are equivalent unless you
  bind the deviation once; continuous threshold `<`/`<=` boundaries are
  measure-zero equivalents — document those in `.cargo/mutants.toml`.

Keep `ax-core` dependency-light; put detector math in `ax-detect`.
