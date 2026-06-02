#!/usr/bin/env python3
"""
stock_anomalies.py — find a stock's anomalous trading days with anomalyx.

A worked example of *consuming the tq1 contract*. It fetches a ticker's daily
history from Yahoo Finance, enriches it with daily-return % and intraday-range %,
shells out to `anomalyx scan`, and then parses the dense JSON envelope —
the dictionary-pinned string table plus the dense finding rows — and maps each
finding's handle back to a calendar date. That handle-to-evidence walk is exactly
what an agent does with the output; the point is that the script reads a typed
contract, never pretty text.

Two modes:
  * single corpus  — point / multivariate / collective anomalies *within* one
                     ticker's series (volume spikes, big moves, regime shifts);
  * `--baseline T` — distributional drift of one window/ticker against another
                     (the dist.ks / dist.psi detectors), e.g. "did volatility
                     regime-change?" or "how does NVDA differ from AMD?".

Usage:
    pip install yfinance            # one-time
    cargo install anomalyx          # or point $ANOMALYX at the binary
    python3 examples/stock_anomalies.py NVDA --period 2y
    python3 examples/stock_anomalies.py NVDA --period 2y --fdr 0.01 --min-severity high
    python3 examples/stock_anomalies.py NVDA --period 1y --baseline AMD

Anything after the known flags is passed straight through to `anomalyx scan`
(e.g. `--top 20`, `--fdr 0.01`, `--no-column-roles`).

Requires: python3, yfinance, and the `anomalyx` binary on PATH (or `$ANOMALYX`).
Exit code mirrors anomalyx: 0 clean, 1 anomalies found, 2 error.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile


def fetch(ticker: str, period: str):
    """Daily OHLCV + return%/range% for `ticker`, as a DataFrame (newest deps)."""
    try:
        import yfinance as yf
    except ImportError:
        sys.exit("yfinance is required: `pip install yfinance`")
    df = yf.download(ticker, period=period, interval="1d", auto_adjust=True, progress=False)
    if df is None or len(df) == 0:
        sys.exit(f"no data returned for {ticker!r} (period={period})")
    # yfinance may return a column MultiIndex for a single ticker; flatten it.
    df.columns = [c[0] if isinstance(c, tuple) else c for c in df.columns]
    df = df.reset_index()
    df["daily_return_pct"] = (df["Close"].pct_change() * 100).round(4)
    df["range_pct"] = ((df["High"] - df["Low"]) / df["Close"] * 100).round(4)
    df = df.dropna().reset_index(drop=True)
    df["Date"] = df["Date"].astype(str)
    return df


def anomalyx_scan(csv_path: str, extra_args: list[str]) -> dict:
    """Run `anomalyx scan` and parse the tq1 envelope. Exits on a tool error."""
    exe = os.environ.get("ANOMALYX", "anomalyx")
    if shutil.which(exe) is None and not os.path.exists(exe):
        sys.exit(f"`{exe}` not found — run `cargo install anomalyx` or set $ANOMALYX")
    proc = subprocess.run(
        [exe, "scan", *extra_args, csv_path], capture_output=True, text=True
    )
    if proc.returncode == 2:  # committed: 0 clean, 1 anomalies, 2 tool error
        sys.exit(f"anomalyx error: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def describe_handle(handle: str, dates: list[str]) -> str:
    """Map a finding handle back to a human-readable 'when/what'."""
    parts = handle.split(":")
    kind = parts[0]
    if kind == "cell":  # cell:COLUMN:row
        return f"{dates[int(parts[2])]}  {parts[1]}"
    if kind == "row":  # row:index  (multivariate — a whole day)
        return f"{dates[int(parts[1])]}  (all columns)"
    if kind == "range":  # range:COLUMN:start:end  (collective level shift)
        a, b = int(parts[2]), min(int(parts[3]), len(dates) - 1)
        return f"{parts[1]}  {dates[a]} -> {dates[b]}"
    if kind == "dist":  # dist:COLUMN  (distributional drift vs baseline)
        return f"{parts[1]}  (distribution)"
    return handle


def report(env: dict, dates: list[str]) -> None:
    dic = env["dict"]
    summ = env["summary"]
    print(
        f"format={env['format']}  rows={env['rows_scanned']}  "
        f"exit={env['exit']}  detected={summ['total']}  max_severity={summ.get('max_severity')}"
    )
    print("roles: " + ", ".join(f"{c['column']}={c['role']}" for c in env.get("roles", [])))
    if scope := env.get("scope"):
        print(f"scope: emitted {scope['emitted']} of {scope['detected']} (dropped {scope['dropped']})")
    print()
    # `rows` is already sorted severity-first by anomalyx; just walk it.
    for row in env["rows"]:
        detector, severity = dic[row[0]], dic[row[4]]
        when = describe_handle(dic[row[2]], dates)
        reason = dic[row[6]]
        print(f"  [{severity:>8}] {detector:<15} {when}")
        print(f"             {reason}")
    if not env["rows"]:
        print("  (no findings)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("ticker", nargs="?", default="NVDA")
    ap.add_argument("--period", default="2y", help="yfinance period (1y, 2y, 5y, max, …)")
    ap.add_argument(
        "--baseline",
        metavar="TICKER",
        help="compare against another ticker for distributional drift",
    )
    ap.add_argument(
        "--baseline-period", help="period for the baseline ticker (default: --period)"
    )
    args, scan_args = ap.parse_known_args()

    tmp = tempfile.mkdtemp(prefix="anomalyx-stock-")
    df = fetch(args.ticker, args.period)
    cur_csv = os.path.join(tmp, f"{args.ticker}.csv")
    df.to_csv(cur_csv, index=False)
    dates = df["Date"].tolist()

    extra = list(scan_args)
    if args.baseline:
        bdf = fetch(args.baseline, args.baseline_period or args.period)
        base_csv = os.path.join(tmp, f"{args.baseline}.csv")
        bdf.to_csv(base_csv, index=False)
        # Compare the *behavioral* distributions (volume / return / volatility);
        # excluding price levels and the Date label keeps drift meaningful.
        extra = ["--baseline", base_csv, "--columns", "daily_return_pct,range_pct,Volume", *extra]
        print(f"# {args.ticker} ({args.period}) vs baseline {args.baseline} — distributional drift\n")
    else:
        print(f"# {args.ticker} ({args.period}) — anomalous trading days\n")

    env = anomalyx_scan(cur_csv, extra)
    report(env, dates)
    sys.exit(0 if env["exit"] == 0 else 1)


if __name__ == "__main__":
    main()
