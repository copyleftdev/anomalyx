# Scan modes

A plain `scan` runs the single-corpus detectors (point, structural shape
checks). Three flags activate the rest; when a flag is absent, the detectors it
would enable report [honest absence](./determinism.md) rather than guessing. A
fourth pair of flags — `--columns` / `--exclude` — narrows *which* columns are
analyzed at all.

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

The regularity bar is the inter-arrival **coefficient of variation** (CV =
stddev / mean); `cad.regularity` fires when CV is below a threshold (default
`0.05`). Tune it with **`--cad-max-cv F`**:

```console
$ anomalyx scan --cadence timestamp beacon.pcap                    # default 0.05
$ anomalyx scan --cadence timestamp --cad-max-cv 0.15 beacon.pcap  # catch jittered beacons
```

A perfectly periodic beacon has CV ≈ 0; real C2 channels add timing jitter to
evade exactly this kind of test. A ~10% jitter (CV ≈ 0.10) slips past the
default but is caught at `--cad-max-cv 0.15` — at the cost of flagging more
merely-regular traffic. The threshold is folded into the envelope's
`config_version` (`cdcv=`), so a non-default bar is a versioned, reproducible
choice, never a hidden one.

> Rows are treated in their given order as the time axis. If your data isn't
> already time-ordered, sort it first.

## `--top N` / `--min-severity S` — output scoping

Detection can surface tens of thousands of findings on a large corpus. These two
flags scope what `scan` *emits* without touching what it *detects*:

```console
$ anomalyx scan --top 50 big.parquet              # the 50 most severe
$ anomalyx scan --min-severity high big.parquet   # only high/critical
$ anomalyx scan --fdr 0.01 --min-severity high --top 25 big.parquet   # compose
```

`--top N` keeps the N most severe findings (the row list is already sorted
severity-first); `--min-severity S` keeps findings at or above `S`
(`info` < `low` < `medium` < `high` < `critical`).

**The scoping is honest.** `summary` (`total`, `by_class`, `max_severity`) and
the **exit code** always describe *everything detected* — so filtering the view
can never make anomalies look absent or flip exit `1`→`0`. When findings are
withheld, the envelope gains a `scope` block recording the filter and the
`detected` / `emitted` / `dropped` counts; `rows` carries only the emitted
subset. Without these flags the block is absent and `rows` is complete.

> This is the volume complement to `--fdr` (which controls *correctness*): FDR
> makes findings statistically defensible, output scoping makes the list
> consumable. Together: "the top N, ≥ severity S, among the FDR-significant set."

## `--fdr Q` — false-discovery-rate control (point detector)

By default the point detector flags every cell whose modified z-score clears a
fixed cutoff. With thousands of cells, a fixed cutoff has no notion of *how many*
cells were tested. `--fdr Q` converts each cell's score to a two-sided p-value
and applies the **Benjamini–Hochberg** procedure within each column, bounding the
expected proportion of false flags at `Q`:

```console
$ anomalyx scan --fdr 0.05 events.parquet     # ≤5% expected false discoveries
```

This is **principled, not arbitrary**: a column that is really just noise stops
contributing chance flags, and the same outlier can be significant in a small
column yet not in a large one (the per-rank bar `(k/m)·Q` shrinks with the number
of cells `m`). The threshold is folded into `config_version` (`pfdr=`), so a
non-default level is a versioned, reproducible choice.

> `--fdr` controls *correctness*, not output *volume*. On genuinely heavy-tailed
> data it can flag **more** cells than the fixed cutoff — those cells really are
> significant at `Q`. To cap volume, pair it with `--columns`/`--exclude` (and
> the planned severity / top-N output scoping).

## `--columns C,..` / `--exclude C,..` — column scope

Restrict detection to a chosen set of columns (`--columns`, an allowlist) or to
everything *but* a set (`--exclude`, a denylist). The two are mutually exclusive.
The projection is applied before any detector runs, and to the `--baseline` too,
so drift comparison stays consistent.

```console
# focus a wide log on the columns that carry signal
$ journalctl -o json | anomalyx scan --columns PRIORITY,_SYSTEMD_UNIT

# or keep everything except journald's identifier/counter/timestamp noise
$ journalctl -o json | anomalyx scan \
    --exclude JOB_ID,_PID,__MONOTONIC_TIMESTAMP,__REALTIME_TIMESTAMP,N_RESTARTS
```

This is the answer to *identifier noise* on wide corpora. The `point` detector
will dutifully flag statistical outliers in every numeric column — including
`JOB_ID`, PIDs, monotonic timestamps and restart counters, where an "outlier" is
real but meaningless. On a raw 20k-entry journald capture that's ~10k findings of
noise; excluding those fields collapses it to a couple hundred that matter.

The scope is **explicit, never heuristic.** anomalyx will not auto-guess which
columns are "interesting" — that would be a guess, and the obvious guess
(drop near-unique columns) would wrongly discard exactly the near-unique numeric
*measurements* the marquee detectors depend on (packet `durationNanos`, span
durations, latencies). You name the scope; the result stays deterministic.

> A column named in `--columns`/`--exclude` that doesn't exist in the corpus is
> a hard error (exit `2`), so a typo can't silently scope a scan down to nothing
> and read as "clean". (The baseline is projected leniently — it's a different
> corpus and need not carry every scoped column.)
