# Architecture

A small workspace of focused crates. The guiding rule: **the contract is
engine-independent**, so the heavy machinery can change without the output
shape moving.

```text
crates/
  ax-core        contract types: RecordSet, the anomaly taxonomy, the tq1
                 envelope, evidence handles, deterministic reductions.
                 Deliberately no heavy deps — keeps the contract independent
                 and the mutation gate fast. (crate: anomalyx-core)
  ax-normalize   any input format → RecordSet. CSV/TSV/NDJSON/JSON via a lean
                 deterministic reader; Parquet/Arrow IPC via the Polars
                 backbone, behind the default-on `polars` feature.
                 (crate: anomalyx-normalize)
  ax-detect      the Detector trait + registry; the nine detectors and their
                 math (assembled from statrs, not reinvented).
                 (crate: anomalyx-detect)
  anomalyx       the four-verb CLI surface — the installable binary.
  ax-validate    NIST StRD validation + stress harness (publish = false).
```

## Engine independence

Polars lives *only* inside `ax-normalize`'s binary-format reader. It reads a
`DataFrame` and lowers it to a `RecordSet`; no Polars type ever reaches a
detector, the envelope, or the contract. That's what lets the text-only build
drop Polars entirely, and what keeps `ax-core` — where the taxonomy and envelope
live — a tiny, dependency-light crate that the mutation gate can sweep quickly.

## Adding a format (the parser plugin system)

`ax-normalize` is a parser-plugin registry. Each format is an independent
`FormatParser` (`id`, `extensions`, content `sniff`, `parse`) living in its own
file under `crates/ax-normalize/src/parsers/`. The `ParserRegistry` resolves a
byte stream by file extension first, then by the highest-confidence sniff
(deterministic: confidences are registered in descending order). Adding a format
is a new `parsers/<fmt>.rs` plus one `register(...)` line in `default_registry` —
no central `match` to edit. See the open `format` issues for the backlog.

## The detector contract

A `Detector` is itself a contract. Given a `ScanContext { current, baseline }`
it either *runs* and emits `Finding`s, or declares honest `Absence`. The
`Registry` runs the set deterministically and merges everything into one
`Report`, which the CLI turns into a `tq1` envelope. Adding a detector is:
implement the trait, register it, and gate it.

## Naming

The crates.io packages are namespaced under the brand (`anomalyx-core`,
`anomalyx-normalize`, `anomalyx-detect`) because the short `ax-*` names were
taken; the in-source module/import names remain `ax_core` etc. via Cargo's
dependency-rename, so the code reads cleanly.
