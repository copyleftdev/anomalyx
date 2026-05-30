# Determinism & honest absence

Two principles run through the whole tool. Both exist because the primary
consumer is an agent, and an agent can't paper over surprises the way a human
can.

## Determinism is UX

> *"Determinism is not just a testing preference. It is user experience for
> agents."*

Same input + same `config_version` ⇒ **byte-identical** output. Concretely:

- **Order-independent reductions.** Floating-point addition is neither
  associative nor commutative, so a naïve sum depends on order. Every reduction
  (mean, variance, MAD, quantiles, PSI, …) sorts its inputs by total order and
  accumulates with compensated (Neumaier) summation — the same multiset of
  values yields the same bits regardless of arrangement. This is exercised on
  real NIST data under reversal and rotation.
- **No wall-clock, no RNG** in the measurement path. Detectors that elsewhere
  rely on randomness (e.g. isolation forests) are replaced with deterministic
  equivalents (Mahalanobis distance).
- **Stable interning and sorting.** The envelope's string table and finding
  order are deterministic, so two runs diff cleanly.
- **A config fingerprint.** Any threshold that could change output also changes
  `config_version`, so you can always tell *the data changed* from *the tool's
  configuration changed*.

## Honest absence

> *"An AI-first instrument should not try to sound intelligent."*

A detector that cannot meaningfully run says so — it never fabricates a clean
result. Absences are first-class, recorded in the envelope's `absent` array with
a machine-readable reason:

```json
"absent": [
  {"detector":"dist.ks","reason":"no baseline provided; distributional drift requires --baseline"},
  {"detector":"ctx.seasonal","reason":"contextual detection needs a declared period ≥ 2 (pass --period N)"},
  {"detector":"mv.mahalanobis","reason":"needs at least 2 numeric columns for a multivariate distance"}
]
```

The same honesty appears at every level:

- A missing cell is `Null`, never `0.0`.
- An unavailable detector contributes *nothing*, not an implied "looks fine."
- An unresolved `explain` handle fails with exit `2`, not a fabricated hit.
- A format built without Polars support rejects Parquet explicitly.
