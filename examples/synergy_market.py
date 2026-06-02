#!/usr/bin/env python3
"""
synergy_market.py — anomalyx (find) + agent-calc (prove) on the live market.

Two contract-first CLIs, chained through their typed JSON envelopes:

  * anomalyx   — *descriptive, assumption-free*: which trading days / regimes
                 broke the pattern (modified-z, Mahalanobis, CUSUM). It never
                 assumes a distribution.
  * agent-calc — *exact*: deterministic statistics on those findings. How
                 absurd is the worst day under the Gaussian a risk system would
                 actually use? Is the regime break anomalyx flagged statistically
                 real (a two-sample t-test)? Exact Pearson r across the basket.

The point of the pairing: anomalyx flags the extremes empirically, then
agent-calc quantifies *why the naive model is the thing that's broken* — fat
tails make "anomalies" the rule, not 1-in-a-million flukes. Both speak
machine-readable contracts, so the detector's output feeds the math kernel with
no prose and no float drift.

Usage:
    pip install yfinance
    cargo install anomalyx                      # or set $ANOMALYX
    # build agent-calc and point $AGENT_CALC at the binary, e.g.:
    #   (cd ../agent-calc && cargo build --release)
    #   export AGENT_CALC=../agent-calc/target/release/agent-calc
    python3 examples/synergy_market.py
    python3 examples/synergy_market.py --market SPY --period 2y --fdr 0.01
    python3 examples/synergy_market.py --tickers SPY,NVDA,TSLA --top 12

Anything after the known flags passes through to `anomalyx scan`. Read-only,
public data, no API key. Exit code mirrors anomalyx: 0 clean, 1 anomalies, 2 error.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

DEFAULT_TICKERS = "SPY,NVDA,AAPL,MSFT,AMZN,META,GOOGL,TSLA"


def resolve(env_var: str, default: str, install_hint: str) -> str:
    exe = os.environ.get(env_var, default)
    if shutil.which(exe) is None and not os.path.exists(exe):
        sys.exit(f"`{exe}` not found — {install_hint} or set ${env_var}")
    return exe


def calc(exe: str, domain: str, req: dict) -> dict:
    """One typed-JSON round-trip to agent-calc; returns the parsed contract."""
    proc = subprocess.run([exe, domain], input=json.dumps(req), capture_output=True, text=True)
    if not proc.stdout.strip():
        sys.exit(f"agent-calc {domain} error: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def fetch(ticker: str, period: str) -> list[tuple]:
    """(date, close, volume, daily_return_pct, range_pct) per session, adjusted."""
    import yfinance as yf

    df = yf.Ticker(ticker).history(period=period, auto_adjust=True)
    if df.empty:
        sys.exit(f"no price history for {ticker!r}")
    rows, prev = [], None
    for idx, r in df.iterrows():
        close, hi, lo = float(r["Close"]), float(r["High"]), float(r["Low"])
        ret = None if prev is None else (close / prev - 1.0) * 100.0
        rng = (hi - lo) / close * 100.0 if close else None
        rows.append((idx.strftime("%Y-%m-%d"), close, float(r["Volume"]), ret, rng))
        prev = close
    return rows


def write_csv(rows: list[tuple], path: str) -> list[str]:
    """Dense CSV for anomalyx; returns the per-row dates (first session dropped)."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["date", "close", "volume", "daily_return_pct", "range_pct"])
        for d, c, v, ret, rng in rows[1:]:
            w.writerow([d, f"{c:.4f}", int(v), f"{ret:.4f}", f"{rng:.4f}"])
    return [r[0] for r in rows[1:]]


def anomalyx_scan(exe: str, csv_path: str, extra: list[str]) -> dict:
    proc = subprocess.run([exe, "scan", *extra, csv_path], capture_output=True, text=True)
    if proc.returncode == 2:
        sys.exit(f"anomalyx error: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def handle_to_date(handle: str, dates: list[str]) -> str:
    p = handle.split(":")
    if p[0] == "cell":
        return f"{dates[int(p[2])]} {p[1]}"
    if p[0] == "row":
        return f"{dates[int(p[1])]} (joint)"
    if p[0] == "range":
        a, b = int(p[2]), min(int(p[3]), len(dates) - 1)
        return f"{p[1]} {dates[a]} -> {dates[b]}"
    if p[0] == "dist":
        return f"{p[1]} (distribution)"
    return handle


def find_cusum_break(env: dict, dates: list[str]) -> tuple[int, str] | None:
    """Locate anomalyx's collective regime shift -> (break_row_index, date)."""
    dic = env["dict"]
    for row in env["rows"]:
        if dic[row[0]] == "coll.cusum":
            p = dic[row[2]].split(":")  # range:column:start:end
            if p[0] == "range":
                idx = min(int(p[2]), len(dates) - 1)
                return idx, dates[idx]
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--tickers", default=DEFAULT_TICKERS, help="comma-separated basket")
    ap.add_argument("--market", help="the index proxy to scan in depth (default: first ticker)")
    ap.add_argument("--period", default="14mo", help="yfinance period (e.g. 1y, 2y, 14mo)")
    args, scan_args = ap.parse_known_args()

    ax = resolve("ANOMALYX", "anomalyx", "run `cargo install anomalyx`")
    ac = resolve("AGENT_CALC", "agent-calc", "build agent-calc")
    tickers = [t.strip().upper() for t in args.tickers.split(",") if t.strip()]
    market = (args.market or tickers[0]).upper()

    print(f"# anomalyx + agent-calc on the live market — {market} in depth, "
          f"basket {','.join(tickers)} (period {args.period})\n")

    # --- anomalyx: find the anomalies in the market proxy ---
    market_rows = fetch(market, args.period)
    tmp = tempfile.mkdtemp(prefix="synergy-")
    csv_path = os.path.join(tmp, "market.csv")
    dates = write_csv(market_rows, csv_path)
    rets = [r[3] for r in market_rows[1:] if r[3] is not None]

    env = anomalyx_scan(ax, csv_path, scan_args)
    dic, summ = env["dict"], env["summary"]
    print(f"## {market}  —  {len(dates)} sessions, {dates[0]} -> {dates[-1]}")
    print(f"   anomalyx: detected={summ['total']}  max_severity={summ.get('max_severity')}")
    if scope := env.get("scope"):
        print(f"   scope: emitted {scope['emitted']} of {scope['detected']}")
    for row in env["rows"]:
        print(f"      [{dic[row[4]]:>8}] {dic[row[0]]:<14} {handle_to_date(dic[row[2]], dates)}")

    # --- agent-calc: exact stats on the same returns ---
    d = calc(ac, "stats", {"intent": "describe_sample", "values": rets})
    print(f"\n   agent-calc describe_sample(daily_return_pct):")
    print(f"      mean={d['mean']:+.4f}%  vol(std)={d['std_dev']:.4f}%  "
          f"skew={d['skewness']:+.3f}  kurtosis={d['kurtosis']:.2f}  (Gaussian=3.0)")

    mn, sd = d["mean"], d["std_dev"]
    worst, best = min(rets), max(rets)
    lo = calc(ac, "stats", {"intent": "normal_cdf", "x": worst, "mean": mn, "std_dev": sd})["value"]
    hi = calc(ac, "stats", {"intent": "normal_cdf", "x": best, "mean": mn, "std_dev": sd})["value"]
    ut = 1.0 - hi
    print(f"   extremeness under {market}'s own fitted Gaussian:")
    print(f"      worst {dates[rets.index(worst)]} {worst:+.2f}% -> P(X<=x)={lo:.3e}"
          + (f"  (~1 in {1/lo:,.0f} sessions)" if lo > 0 else "  (underflow: 'impossible')"))
    print(f"      best  {dates[rets.index(best)]} {best:+.2f}% -> P(X>=x)={ut:.3e}"
          + (f"  (~1 in {1/ut:,.0f} sessions)" if ut > 0 else "  (underflow: a Gaussian calls it impossible)"))

    # --- synergy: is the regime break anomalyx flagged statistically real? ---
    brk = find_cusum_break(env, dates)
    if brk:
        idx, when = brk
        before, after = rets[:idx], rets[idx:]
        if len(before) >= 2 and len(after) >= 2:
            t = calc(ac, "stats", {"intent": "two_sample_t", "sample1": before,
                                   "sample2": after, "equal_var": False})
            print(f"\n   regime break @ {when} (anomalyx coll.cusum) — agent-calc two-sample t (Welch):")
            print(f"      before n={len(before)}  vs  after n={len(after)}: "
                  f"t={t['statistic']:.3f}  p={t['p_value']:.3e}  -> "
                  f"{'REAL shift in mean return' if t['reject_h0'] else 'not significant'} (a=0.05)")

    # --- basket: exact Pearson r to the market proxy + each name's own risk ---
    base = {d_: r for d_, _, _, r, _ in market_rows[1:] if r is not None}
    print(f"\n## Basket — exact Pearson r to {market} + own daily vol")
    for t in tickers:
        if t == market:
            continue
        rws = fetch(t, args.period)
        pairs = [(base[dd], r) for dd, _, _, r, _ in rws[1:] if r is not None and dd in base]
        if len(pairs) < 3:
            continue
        r = calc(ac, "stats", {"intent": "correlation",
                               "x": [a for a, _ in pairs], "y": [b for _, b in pairs]})
        own = calc(ac, "stats", {"intent": "describe_sample",
                                 "values": [b for _, b in pairs]})
        big = max(abs(own["min"]), abs(own["max"]))
        print(f"   {t:<6} r_vs_{market}={r['pearson_r']:+.3f}   "
              f"own vol={own['std_dev']:.3f}%   largest move={big:.2f}%")

    sys.exit(0 if env["exit"] == 0 else 1)


if __name__ == "__main__":
    main()
