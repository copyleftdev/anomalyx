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
