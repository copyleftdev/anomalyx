# Examples

Worked examples of using anomalyx on real data. These live outside the Cargo
workspace (they shell out to the installed `anomalyx` binary), so they don't
affect the build or the gates.

## `stock_anomalies.py`

Fetches a stock's daily history from Yahoo Finance, enriches it with daily-return
and intraday-range columns, runs `anomalyx scan`, and prints the anomalous
trading days — mapping each finding's **handle back to a calendar date**. It's a
compact demonstration of *consuming the `tq1` contract*: it parses the dense JSON
envelope (the dictionary + dense finding rows), not pretty text.

```sh
pip install yfinance          # one-time
cargo install anomalyx        # or set $ANOMALYX to the binary path

# Anomalous trading days within one ticker (point / multivariate / collective):
python3 examples/stock_anomalies.py NVDA --period 2y

# Only the strongest, with false-discovery-rate control:
python3 examples/stock_anomalies.py NVDA --period 2y --fdr 0.01 --min-severity high

# Distributional drift of one ticker's behavior against another:
python3 examples/stock_anomalies.py NVDA --period 1y --baseline AMD
```

Any extra flags are passed straight through to `anomalyx scan` (e.g. `--top 20`,
`--no-column-roles`). The exit code mirrors anomalyx: `0` clean, `1` anomalies
found, `2` error.

On real NVDA history this surfaces, for example, the 2025‑01‑27 DeepSeek selloff
(top volume + the single largest multivariate outlier), the April‑2025 tariff
volatility, and the second‑half‑2025 price regime shift (`coll.cusum`) — and in
`--baseline` mode, that NVDA's volume and volatility *distributions* differ
sharply from a peer's.

## `synergy_market.py`

Pairs anomalyx with [`agent-calc`](https://github.com/copyleftdev/agent-calc) —
another contract-first CLI, an *exact* math kernel — on the live market. Two
typed-JSON contracts chained: anomalyx is **descriptive** (which days/regimes
broke the pattern, assumption-free); agent-calc is **exact** (what those
findings mean as deterministic statistics).

```sh
pip install yfinance
cargo install anomalyx                                  # or set $ANOMALYX
(cd ../agent-calc && cargo build --release)             # then point $AGENT_CALC at it
export AGENT_CALC=../agent-calc/target/release/agent-calc

python3 examples/synergy_market.py
python3 examples/synergy_market.py --market SPY --period 2y --fdr 0.01
python3 examples/synergy_market.py --tickers SPY,NVDA,TSLA --top 12
```

anomalyx finds the anomalous days and the price regime shift (`point.modz` /
`mv.mahalanobis` / `coll.cusum`); the detector output then feeds `agent-calc`,
which computes the exact return distribution (`describe_sample` — note the
fat-tailed kurtosis), the worst day's tail probability under a fitted Gaussian
(`normal_cdf` — often "1-in-millions", i.e. the *model* is what's broken), a
two-sample t-test on the returns either side of the CUSUM break (`two_sample_t`
— is the regime shift a real change in *mean* return, or only in trajectory?),
and exact Pearson `r` of each basket name to the market. The punchline is that
both halves emit machine-readable contracts, so findings flow into the math
kernel with no prose and no float drift.

## `journal_anomalies.py`

Finds anomalies in the systemd journal (Linux + systemd). Pipes
`journalctl -o json` to anomalyx on **stdin** (so it content-sniffs as `journal`,
not plain JSON) and maps each finding back to its **timestamp / unit / message**.

```sh
python3 examples/journal_anomalies.py --lines 20000
python3 examples/journal_anomalies.py --since "2 hours ago" --top 20

# Distributional drift between two windows (which units / priorities shifted):
python3 examples/journal_anomalies.py --since "1 hour ago" \
        --baseline-since "3 hours ago" --baseline-until "1 hour ago"
```

Single-window finds per-unit content anomalies (e.g. CPU‑usage spikes); the
`--baseline-since` mode runs `dist.chi2` over `_SYSTEMD_UNIT` / `PRIORITY` to flag
units that appeared or whose share changed. Column roles keep journald's many
id / counter / timestamp fields out of the way automatically.

## `polymarket_anomalies.py`

Pulls a prediction market's price history from Polymarket's public APIs
(read-only, no key), enriches it with the per‑step probability change, and finds
the **information shocks** — sharp probability jumps (`point` / `mv`) and
sustained regime shifts in the odds (`coll.cusum`).

```sh
python3 examples/polymarket_anomalies.py                 # top market by volume
python3 examples/polymarket_anomalies.py "bitcoin"       # first match by question/slug
python3 examples/polymarket_anomalies.py "fed" --top 15  # search first, then scan flags
```

> Pass any search term **before** scan flags (the term is an optional positional).

Maps each finding back to its UTC timestamp; the `timestamp` column is
auto-classified a `sequence` and skipped, so the findings are about the odds, not
the clock.
