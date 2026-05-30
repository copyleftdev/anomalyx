# Anomaly taxonomy

"Anomaly" is not one thing. anomalyx classifies every finding into one of seven
classes, so you reason about the *kind* of deviation, not just that "something
is off." Nine detectors implement the taxonomy today.

| Class | What it catches | Detector(s) |
|---|---|---|
| `point` | a single value far from its column's distribution | `point.modz` |
| `distributional` | the distribution shifted vs. a baseline | `dist.ks`, `dist.psi`, `dist.chi2` |
| `structural` | schema / type / null-rate / cardinality violations | `struct.schema` |
| `multivariate` | a row that breaks the joint structure across columns | `mv.mahalanobis` |
| `contextual` | a value anomalous only in context (seasonal) | `ctx.seasonal` |
| `collective` | a subsequence that is jointly anomalous (level shift) | `coll.cusum` |
| `cadence` | timing too *regular* to be organic (automation) | `cad.regularity` |

Every detector is deterministic — no RNG, no wall-clock — which is what lets
anomalyx meet its byte-reproducibility guarantee. Where an off-the-shelf method
would fight that (an isolation forest's RNG, for instance), anomalyx uses a
deterministic equivalent.

## point — `point.modz`

Per-column univariate outliers via the Iglewicz–Hoaglin **modified z-score**,
`M = 0.6745·(x − median)/MAD`. MAD (median absolute deviation) is robust: a few
wild values don't inflate the spread and mask each other. Falls back to mean/σ
when MAD collapses; a truly constant column flags nothing. Emits a `cell` handle.

## distributional — `dist.ks` / `dist.psi` / `dist.chi2`

Compare the *current* corpus against a `--baseline`:

- **`dist.ks`** — two-sample Kolmogorov–Smirnov on numeric columns (shape/location shift), with an asymptotic p-value.
- **`dist.psi`** — Population Stability Index over baseline-quantile bins (how much mass moved); the binned cousin of KL divergence.
- **`dist.chi2`** — chi-square over category frequencies for categorical columns; also surfaces brand-new categories.

Without a baseline these report [honest absence](./determinism.md). Emit `dist` handles.

## structural — `struct.schema`

Shape, not values. Single-corpus: columns with conflicting cell types (`Mixed`)
and columns whose null fraction exceeds a threshold. With a `--baseline`: a
schema diff — columns added, dropped, or whose inferred type changed. Emits
`col` handles.

## multivariate — `mv.mahalanobis`

A row can be unremarkable on every axis yet a glaring **joint** outlier — e.g.
it breaks the correlation the rest of the data obeys. The **Mahalanobis
distance** measures distance from the centroid in units that account for each
feature's spread *and* the covariance between features. Squared distance ~ χ²(d),
so a principled per-row p-value falls out. Own deterministic Cholesky solve, no
RNG. Emits a `row` handle.

## contextual — `ctx.seasonal`

A daytime traffic level at 3am; a weekday volume on a Sunday. Given a period
`--period N`, each point is scored only against its own phase (`row mod N`) — its
seasonal peers — using the same robust modified z-score. Seasonality is never
guessed: without a period it reports honest absence.

## collective — `coll.cusum`

A sustained shift in level is the canonical collective anomaly. CUSUM finds the
change point that maximizes the cumulative deviation from the mean; when the
standardized two-segment shift is large, the post-change segment is flagged as a
`range` handle.

## cadence — `cad.regularity`

The inverse of every other detector: timing too *regular* to be organic — the
metronomic signature of automation. On a column named by `--cadence COL`, the
inter-arrival intervals' coefficient of variation (`CV = σ/μ`) near zero is the
tell. Opt-in, because which column means "time" is never guessed.
