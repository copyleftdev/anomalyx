# Input & normalization

> *"Given any corpus of information regardless of its format, we'll normalize
> it."*

Every supported format is lowered to one engine-independent record model — a
`RecordSet` of named, typed columns — and detectors only ever see that. The
contract stays stable while the backend underneath it changes.

## Supported formats

| Format | Extensions | Backend |
|---|---|---|
| CSV | `.csv` | lean deterministic reader |
| TSV | `.tsv`, `.tab` | lean deterministic reader |
| NDJSON | `.ndjson`, `.jsonl` | lean deterministic reader |
| JSON | `.json` | lean deterministic reader |
| Parquet | `.parquet`, `.pq` | Polars / Arrow |
| Arrow IPC | `.arrow`, `.ipc`, `.feather` | Polars / Arrow |

Format is resolved by extension first, then by content sniff (binary magic
numbers `PAR1` / `ARROW1` are checked before UTF-8 text sniffing). An
unrecognized stream is an explicit error, never a silent guess.

## The record model

A `RecordSet` is named columns of equal length, each with an inferred type:
`Int`, `Float`, `Bool`, `Str`, `Unknown`, or `Mixed` (conflicting concrete types
— itself a structural signal). Values collapse into a small closed set, and
**absence is explicit**: a missing cell is `Null`, never a sentinel `0.0` that
would skew a mean.

```text
amount,tier        →   column "amount": Int   [10, 11, 9, …]
10,a                   column "tier":   Str   ["a", "b", "c", …]
11,b
```

Binary columnar formats live entirely behind this boundary: the Polars
`DataFrame` is converted to a `RecordSet` (integers fold to `i64`, floats to
`f64` with non-finite → `Null`, unsupported logical types preserved as their
string form), so no Polars type ever reaches a detector. Text formats never
touch Polars at all.
