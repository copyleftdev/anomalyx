# Worked examples

The repository's [`examples/`](https://github.com/copyleftdev/anomalyx/tree/main/examples)
directory holds small, runnable programs that use anomalyx on **real data**. They
exist to demonstrate one thing the contract makes possible: an agent (or a
30-line script) can *consume the `tq1` envelope directly* — parse the dense
finding rows and the dict-pinned string table, then map each
[handle](./envelope.md) back to a row, cell, or timestamp — rather than scraping
human-readable text.

They live outside the Cargo workspace and shell out to the installed `anomalyx`
binary, so they have no effect on the build or the [quality gates](./gates.md).
Each mirrors anomalyx's exit code (`0` clean, `1` anomalies, `2` error).

## The examples

| Example | Data | What it surfaces |
|---|---|---|
| `stock_anomalies.py` | Yahoo Finance daily history | anomalous trading days; distributional drift vs. another ticker |
| `journal_anomalies.py` | `journalctl -o json` (systemd) | rare priorities, bursts, per-unit content spikes; drift between two windows |
| `polymarket_anomalies.py` | Polymarket public APIs | information shocks (`point`/`mv`) and odds regime shifts (`coll.cusum`) |
| `synergy_market.py` | Yahoo Finance + `agent-calc` | anomalyx *finds*; the exact-math kernel *proves* (tail probability, a t-test across the regime break, exact correlations) |

Each maps the handle in every finding back to a calendar date / timestamp,
so the output reads as *"this day, this column, this kind of deviation"*.

## Contracts composing with contracts

`synergy_market.py` is the clearest illustration of why a machine-readable
contract matters. anomalyx is **descriptive and assumption-free** — it reports
*which* days and regimes broke the pattern (`point.modz`, `mv.mahalanobis`,
`coll.cusum`), never assuming a distribution. Its findings then flow, as typed
JSON, straight into [`agent-calc`](https://github.com/copyleftdev/agent-calc) —
a sibling contract-first CLI that does **exact** statistics: the return
distribution's fat-tailed kurtosis, the worst day's tail probability under a
fitted Gaussian (routinely *one-in-millions* — i.e. the naive risk model is what
is broken), a two-sample *t*-test across the detected regime break (a real shift
in the *mean*, or only the trajectory?), and exact correlations across a basket.

Two executables, two contracts, no prose and no float drift in between — which is
the whole thesis: *the executable is the contract.*

See [`examples/README.md`](https://github.com/copyleftdev/anomalyx/blob/main/examples/README.md)
for the exact commands and prerequisites.
