# anomalyx

[![crates.io](https://img.shields.io/crates/v/anomalyx.svg)](https://crates.io/crates/anomalyx)
[![CI](https://github.com/copyleftdev/anomalyx/actions/workflows/ci.yml/badge.svg)](https://github.com/copyleftdev/anomalyx/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/copyleftdev/anomalyx)

**Contract-first anomaly detection over arbitrary corpora.**

anomalyx is a deterministic Rust CLI built on the thesis of
[*AI Tools Need Contracts, Not Prompts*][article]: **the executable is the
contract.** Point it at **~30 formats** — logs, security telemetry, packet
captures, flow records, observability streams, spreadsheets, and data-lake files
([the full set](./formats.md)) — and it normalizes each into one typed record
model, runs a battery of typed anomaly detectors, and returns a dense, versioned,
machine-readable envelope an agent (or a human) can trust — not pretty text that
has to be scraped.

[article]: https://dev.to/copyleftdev/ai-tools-need-contracts-not-prompts-5ca3

```console
$ printf 'id,amount\n1,10\n2,11\n3,9\n4,10\n5,12\n6,11\n7,10\n8,9\n9,9999\n' | anomalyx scan
{"protocol":"anomalyx/tq1",...,"rows":[[0,1,2,1.0,3,4544.43,4]],...,"exit":1}

$ ... | anomalyx explain cell:amount:8
{"evidence":{"kind":"cell","column":"amount","row":8,"value":{"t":"int","v":9999}},"findings":[...]}
```

## Why it exists

Humans paper over vague tools with context and memory; agents can't. A tool
whose behavior lives in prose, convention, and tribal knowledge is one an agent
will eventually step on. anomalyx is shaped as an **executable contract**:

- A **minimal, discoverable surface** — four verbs: `describe`, `schema`,
  `scan`, `explain`.
- **Typed, dense output** — a versioned `tq1` JSON envelope with a
  dictionary-pinned string table and stable evidence handles, not prose.
- **Determinism as UX** — same input + same config fingerprint yields
  byte-identical output. No wall-clock, no RNG in the measurement path.
- **Honest absence** — a detector that can't run says so; it never fabricates a
  clean result. Exit codes are committed: `0` clean, `1` anomalies, `2` error.

## What makes it trustworthy

- **Nine detectors across a seven-class taxonomy** — point, distributional,
  structural, multivariate, contextual, collective, and cadence anomalies.
- **Any corpus** — CSV, TSV, NDJSON, JSON, Parquet, and Arrow IPC, all lowered
  to one engine-independent record model.
- **Proven correct** — the statistical core is validated against the
  [NIST Statistical Reference Datasets](./validation.md) (certified to 15
  digits), and every crate passes a **0-surviving-mutant** mutation gate on top
  of property-based tests.

Start with [Install](./install.md), then [the four-verb contract](./contract.md).
