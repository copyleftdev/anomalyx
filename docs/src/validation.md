# Validation against NIST

Every detector rests on a small set of deterministic reductions (mean, standard
deviation, …). "anomalyx is mathematically correct" is therefore a *checked*
claim, not an assertion: those reductions are validated against the
[**NIST Statistical Reference Datasets (StRD)**][strd] — the canonical,
certified-to-15-digits truth for univariate summary statistics. The datasets are
vendored offline, so validation is reproducible with no network.

[strd]: https://www.itl.nist.gov/div898/strd/univ/homepage.html

Results are scored by NIST's own metric, the **log relative error** (the number
of correct significant digits):

- `mean` reproduces every certified value to **≥ 15 digits**.
- `std_dev` reaches **≥ 13 digits** on well-conditioned data.

## The precision proof

The `NumAcc3` / `NumAcc4` datasets are *torture tests*: a mean near 10⁶–10⁷ with
a standard deviation of exactly `0.1`. The textbook one-pass variance
(`Σx² − (Σx)²/n`) suffers catastrophic cancellation here. anomalyx's compensated
two-pass reduction does not:

| dataset | `anomalyx` std (correct digits) | naïve one-pass |
|---|---|---|
| `NumAcc3` | **9.46** | 1.14 |
| `NumAcc4` | **8.25** | **0.00** — zero correct digits |
| `Michelson` | 13.84 | 8.28 |

On `NumAcc4` the textbook formula gets *nothing* right; anomalyx tracks NIST to
~8 digits — the ceiling imposed by the f64 representation of the inputs
themselves, which is all NIST expects. This is a checked demonstration that the
determinism-and-precision design is load-bearing, not decorative.

## Stress tests

Beyond certified values, the harness verifies behavior against known ground
truth:

- **Ground-truth recovery** — planted outliers are flagged exactly, with no
  false positives or negatives.
- **Order independence** — `det_sum` is bit-identical under reversal and
  rotation on real 5000-point NIST data.
- **Reproducibility at scale** — a 40k-row scan serializes identically across
  runs.
