#!/usr/bin/env python3
"""
polymarket_anomalies.py — find information shocks in a Polymarket market.

A prediction market's implied probability is usually smooth; a sudden jump is an
information shock (news, a debate, a resolution). This example pulls a market's
price history from Polymarket's public APIs (Gamma for discovery, CLOB for the
series), enriches it with the per-step probability change, runs `anomalyx scan`,
and maps each finding back to its timestamp — another worked example of consuming
the `tq1` contract on a real time series.

What anomalyx surfaces here:
  * point.modz on `prob_change`  — the sharp probability jumps (the news days);
  * coll.cusum on `prob`         — sustained regime shifts in the odds;
  * the `timestamp` column is auto-classified a sequence and skipped.

Usage:
    cargo install anomalyx            # or set $ANOMALYX
    python3 examples/polymarket_anomalies.py                 # top market by volume
    python3 examples/polymarket_anomalies.py "bitcoin"       # first match by question/slug
    python3 examples/polymarket_anomalies.py "fed" --top 15 --fidelity 60

Anything after the known flags passes through to `anomalyx scan`. Read-only,
public data, no API key. Requires: python3 + the `anomalyx` binary (or $ANOMALYX).
Exit code mirrors anomalyx: 0 clean, 1 anomalies found, 2 error.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

GAMMA = "https://gamma-api.polymarket.com"
CLOB = "https://clob.polymarket.com"


def _get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "anomalyx-example/1.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def pick_market(search: str | None, candidates: int) -> tuple[str, str]:
    """Return (question, clob_token_id) for the chosen market (YES outcome)."""
    url = (
        f"{GAMMA}/markets?closed=false&order=volumeNum&ascending=false"
        f"&limit={max(candidates, 1)}"
    )
    markets = json.loads(_get(url))
    needle = (search or "").lower()
    for m in markets:
        ids = m.get("clobTokenIds")
        if not ids:
            continue
        text = f"{m.get('question', '')} {m.get('slug', '')}".lower()
        if needle and needle not in text:
            continue
        return m.get("question") or m.get("slug") or "?", json.loads(ids)[0]
    sys.exit(f"no open market with price history matched {search!r}")


def fetch_history(token: str, fidelity: int) -> list[tuple[int, float]]:
    url = f"{CLOB}/prices-history?market={urllib.parse.quote(token)}&interval=max&fidelity={fidelity}"
    pts = json.loads(_get(url)).get("history", [])
    if len(pts) < 10:
        sys.exit("not enough price history for that market")
    return [(int(p["t"]), float(p["p"])) for p in pts]


def write_csv(points: list[tuple[int, float]], path: str) -> list[str]:
    """Write timestamp/prob/prob_change; return the readable timestamps."""
    stamps = []
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "prob", "prob_change"])
        prev = None
        for t, p in points:
            when = dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
            stamps.append(when)
            w.writerow([when, f"{p:.6f}", "" if prev is None else f"{p - prev:.6f}"])
            prev = p
    return stamps[1:]  # the first row has an empty prob_change and is dropped on parse


def anomalyx_scan(csv_path: str, extra: list[str]) -> dict:
    exe = os.environ.get("ANOMALYX", "anomalyx")
    if shutil.which(exe) is None and not os.path.exists(exe):
        sys.exit(f"`{exe}` not found — run `cargo install anomalyx` or set $ANOMALYX")
    proc = subprocess.run([exe, "scan", *extra, csv_path], capture_output=True, text=True)
    if proc.returncode == 2:
        sys.exit(f"anomalyx error: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def describe_handle(handle: str, dates: list[str]) -> str:
    p = handle.split(":")
    if p[0] == "cell":
        return f"{dates[int(p[2])]}  {p[1]}"
    if p[0] == "row":
        return f"{dates[int(p[1])]}  (all columns)"
    if p[0] == "range":
        a, b = int(p[2]), min(int(p[3]), len(dates) - 1)
        return f"{p[1]}  {dates[a]} -> {dates[b]}"
    if p[0] == "dist":
        return f"{p[1]}  (distribution)"
    return handle


def report(env: dict, dates: list[str]) -> None:
    dic = env["dict"]
    summ = env["summary"]
    print(
        f"format={env['format']}  rows={env['rows_scanned']}  exit={env['exit']}  "
        f"detected={summ['total']}  max_severity={summ.get('max_severity')}"
    )
    print("roles: " + ", ".join(f"{c['column']}={c['role']}" for c in env.get("roles", [])))
    if scope := env.get("scope"):
        print(f"scope: emitted {scope['emitted']} of {scope['detected']} (dropped {scope['dropped']})")
    print()
    for row in env["rows"]:
        print(f"  [{dic[row[4]]:>8}] {dic[row[0]]:<15} {describe_handle(dic[row[2]], dates)}")
        print(f"             {dic[row[6]]}")
    if not env["rows"]:
        print("  (no findings)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("search", nargs="?", help="match a market by question/slug (else top volume)")
    ap.add_argument("--candidates", type=int, default=50, help="markets to consider when matching")
    ap.add_argument("--fidelity", type=int, default=60, help="price-history resolution in minutes")
    args, scan_args = ap.parse_known_args()

    question, token = pick_market(args.search, args.candidates)
    points = fetch_history(token, args.fidelity)
    tmp = tempfile.mkdtemp(prefix="anomalyx-polymarket-")
    csv_path = os.path.join(tmp, "market.csv")
    dates = write_csv(points, csv_path)

    span = f"{points[0][0]} .. {points[-1][0]}"
    print(f"# {question}")
    print(f"# {len(points)} points, prob {points[0][1]:.3f} -> {points[-1][1]:.3f}\n")
    env = anomalyx_scan(csv_path, scan_args)
    report(env, dates)
    sys.exit(0 if env["exit"] == 0 else 1)


if __name__ == "__main__":
    main()
