# Scan modes

A plain `scan` runs the single-corpus detectors (point, structural shape
checks). Three flags activate the rest; when a flag is absent, the detectors it
would enable report [honest absence](./determinism.md) rather than guessing.

## `--baseline B` — drift & schema diff

Compares the current corpus against baseline `B`. Activates the distributional
detectors (`dist.ks`, `dist.psi`, `dist.chi2`) and the schema-diff half of
`struct.schema`.

```console
$ anomalyx scan --baseline last_week.parquet this_week.parquet
# flags columns whose distribution shifted, plus added/dropped/type-changed columns
```

The envelope gains a `baseline` field recording the comparison source.

## `--period N` — seasonal / contextual

Treats rows as an ordered time series of period `N` and runs `ctx.seasonal`,
comparing each point to its phase peers (`row mod N`).

```console
$ anomalyx scan --period 7 daily_metrics.csv     # weekly seasonality
```

A value can be perfectly ordinary globally yet wrong *for its phase* — e.g. a
50 where phase 0 normally sits near 0. Without `--period`, `ctx.seasonal` is
honestly absent; seasonality is never inferred.

## `--cadence COL` — metronomic timing

Reads column `COL` as event times and runs `cad.regularity`, flagging
suspiciously regular inter-arrival intervals (automation).

```console
$ anomalyx scan --cadence ts events.csv
# flags COL if its inter-arrival coefficient of variation is near zero
```

Organic streams are ragged; a metronome is a tell. Opt-in, because which column
means "time" is never guessed.

> Rows are treated in their given order as the time axis. If your data isn't
> already time-ordered, sort it first.
