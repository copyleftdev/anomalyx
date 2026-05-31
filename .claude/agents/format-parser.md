---
name: format-parser
description: Implements a new input-format parser plugin for ax-normalize (one of the `format` issues). Use when adding support for a file format like Parquet, logfmt, syslog, PCAP, xlsx, etc.
tools: Read, Edit, Write, Grep, Glob, Bash
model: inherit
---

You add a new format to anomalyx's parser-plugin registry. Formats are plugins:
one file under `crates/ax-normalize/src/parsers/`, registered in
`parsers/mod.rs::default_registry`. There is no central match to edit.

## Procedure

1. Read the target `format` issue and `crates/ax-normalize/src/parser.rs` to
   internalize the `FormatParser` trait and `ParserRegistry` resolution
   (extension first, then highest-confidence `sniff`; confidences are registered
   in strictly descending order — `MAGIC > STRONG > TEXT > FALLBACK`).
2. Study an existing parser of the same shape: `parsers/delimited.rs` (text),
   `parsers/json.rs` / `ndjson.rs` (record-shaped, reuse `table::TableBuilder`),
   or `parsers/columnar.rs` (binary, behind `#[cfg(feature = "polars")]`).
3. Create `parsers/<fmt>.rs` implementing `FormatParser`:
   - `id()` — stable, lowercase, recorded in the envelope `format` field.
   - `extensions()` — claimed file extensions (lowercase, no dot).
   - `sniff()` — content confidence, or `None`. Binary magic → `MAGIC`; a
     distinctive shape that must beat the CSV fallback → `STRONG`/`TEXT`.
   - `parse()` — bytes → `Vec<Column>`. Map values into the closed `Value` set
     (`Int`/`Float`/`Bool`/`Str`/`Null`). **Honest absence**: missing/unparseable
     cells become `Null`, never a sentinel. Errors are `AxError::Parse`.
4. Register it in `default_registry` (mind ordering for sniff tie-breaks).
5. If it needs a new dependency, add it to `crates/ax-normalize/Cargo.toml`
   (feature-gate heavy/optional deps like the Polars formats are).

## Definition of done (non-negotiable)

- Deterministic: stable column order, no wall-clock/RNG.
- Tests in the new file: a roundtrip, extension-resolution and sniff-confidence,
  and a malformed-input error. Add a feature-gated test if behind a feature.
- `cargo fmt --all`, `cargo clippy -p anomalyx-normalize --all-targets -- -D warnings`,
  `cargo test -p anomalyx-normalize` (and `--no-default-features` if relevant).
- `cargo mutants -p anomalyx-normalize` → **0 surviving (missed) mutants**.
  Pin behavior with exact-value tests; a true equivalent mutant gets a documented
  entry in `.cargo/mutants.toml`, never a blanket suppression.

Touch only `ax-normalize`. Do not change the detector, CLI, or contract crates.
