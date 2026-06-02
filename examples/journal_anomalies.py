#!/usr/bin/env python3
"""
journal_anomalies.py — find anomalies in the systemd journal with anomalyx.

Captures journald entries as JSON, scans them, and reports the anomalous log
entries — mapping each finding back to its timestamp / unit / message. A worked
example of the tq1 contract on *log telemetry* (Linux + systemd only).

The journal is piped to `anomalyx` on **stdin** on purpose: the journal parser
is content-sniffed (a `.json` file would route to the plain-JSON parser). With
column roles on (the default), anomalyx skips journald's many id / counter /
timestamp fields automatically, so the findings are about content, not noise.

Two modes:
  * single window   — point / structural / collective anomalies within one
                      capture (a rare PRIORITY level, a sparse field, a burst);
  * `--baseline-since` — distributional drift of a recent window against an
                      earlier one: which units appeared or changed share, did the
                      error-level mix shift (`dist.chi2` on `_SYSTEMD_UNIT` /
                      `PRIORITY`). Scoped to those interpretable fields so the
                      free-text `MESSAGE` column doesn't drown it in noise.

Usage:
    cargo install anomalyx        # or set $ANOMALYX to the binary path
    python3 examples/journal_anomalies.py --lines 20000
    python3 examples/journal_anomalies.py --since "2 hours ago" --top 20
    python3 examples/journal_anomalies.py --since "1 hour ago" \
            --baseline-since "3 hours ago" --baseline-until "1 hour ago"

Anything after the known flags passes through to `anomalyx scan`.
Requires: python3, journalctl, and the `anomalyx` binary (or `$ANOMALYX`).
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

# Drift is only interpretable on a few journald fields; the rest is id noise
# (skipped by roles anyway) or free-text MESSAGE (every line "new").
DRIFT_COLUMNS = "PRIORITY,_SYSTEMD_UNIT"


def journalctl(selectors: list[str]) -> bytes:
    """Capture journald entries as JSON bytes for the given selectors."""
    if shutil.which("journalctl") is None:
        sys.exit("journalctl not found — this example needs Linux + systemd")
    proc = subprocess.run(
        ["journalctl", "--no-pager", "-o", "json", *selectors],
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit(f"journalctl failed: {proc.stderr.decode(errors='replace').strip()}")
    if not proc.stdout.strip():
        sys.exit("journalctl returned no entries for that window")
    return proc.stdout


def context(raw: bytes) -> list[tuple[str, str, str]]:
    """Per-entry (timestamp, unit/comm, message) for mapping findings back."""
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            out.append(("?", "?", "?"))
            continue
        us = e.get("__REALTIME_TIMESTAMP")
        ts = "?"
        if isinstance(us, str) and us.isdigit():
            import datetime

            ts = datetime.datetime.fromtimestamp(
                int(us) / 1e6, datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
        who = e.get("_SYSTEMD_UNIT") or e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "?"
        msg = e.get("MESSAGE") or ""
        if isinstance(msg, list):  # journald can encode MESSAGE as a byte array
            msg = ""
        out.append((ts, str(who), str(msg)[:80]))
    return out


def anomalyx_scan(stdin_bytes: bytes, extra_args: list[str]) -> dict:
    exe = os.environ.get("ANOMALYX", "anomalyx")
    if shutil.which(exe) is None and not os.path.exists(exe):
        sys.exit(f"`{exe}` not found — run `cargo install anomalyx` or set $ANOMALYX")
    proc = subprocess.run(
        [exe, "scan", *extra_args], input=stdin_bytes, capture_output=True
    )
    if proc.returncode == 2:
        sys.exit(f"anomalyx error: {proc.stderr.decode(errors='replace').strip()}")
    return json.loads(proc.stdout)


def describe_handle(handle: str, ctx: list[tuple[str, str, str]]) -> str:
    parts = handle.split(":")
    kind = parts[0]
    if kind == "cell":  # cell:COLUMN:row
        ts, who, _ = ctx[int(parts[2])]
        return f"{ts} [{who}]  {parts[1]}"
    if kind == "row":  # row:index  (multivariate)
        ts, who, msg = ctx[int(parts[1])]
        return f"{ts} [{who}]  {msg}"
    if kind == "range":  # range:COLUMN:start:end
        a, b = int(parts[2]), min(int(parts[3]), len(ctx) - 1)
        return f"{parts[1]}  {ctx[a][0]} -> {ctx[b][0]}"
    if kind == "dist":  # dist:COLUMN
        return f"{parts[1]}  (distribution)"
    return handle


def report(env: dict, ctx: list[tuple[str, str, str]]) -> None:
    dic = env["dict"]
    summ = env["summary"]
    print(
        f"format={env['format']}  rows={env['rows_scanned']}  "
        f"exit={env['exit']}  detected={summ['total']}  max_severity={summ.get('max_severity')}"
    )
    roles = {c["role"] for c in env.get("roles", [])}
    print(f"columns={len(env.get('roles', []))}  roles_present={sorted(roles)}")
    if scope := env.get("scope"):
        print(f"scope: emitted {scope['emitted']} of {scope['detected']} (dropped {scope['dropped']})")
    print()
    for row in env["rows"]:
        detector, severity = dic[row[0]], dic[row[4]]
        print(f"  [{severity:>8}] {detector:<15} {describe_handle(dic[row[2]], ctx)}")
        print(f"             {dic[row[6]]}")
    if not env["rows"]:
        print("  (no findings)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--since", help="journalctl --since (e.g. '2 hours ago')")
    ap.add_argument("--lines", type=int, help="last N entries instead of --since")
    ap.add_argument("--baseline-since", help="drift mode: baseline window start")
    ap.add_argument("--baseline-until", help="drift mode: baseline window end")
    args, scan_args = ap.parse_known_args()

    cur_sel = ["-n", str(args.lines)] if args.lines else (
        ["--since", args.since] if args.since else ["-n", "10000"]
    )
    raw = journalctl(cur_sel)
    ctx = context(raw)

    extra = list(scan_args)
    if args.baseline_since:
        bsel = ["--since", args.baseline_since]
        if args.baseline_until:
            bsel += ["--until", args.baseline_until]
        braw = journalctl(bsel)
        tmp = tempfile.mkdtemp(prefix="anomalyx-journal-")
        # No `.json` extension → content-sniffed as `journal`, not plain JSON.
        bpath = os.path.join(tmp, "baseline_journal")
        with open(bpath, "wb") as f:
            f.write(braw)
        if "--columns" not in extra and "--exclude" not in extra:
            extra = ["--columns", DRIFT_COLUMNS, *extra]
        extra = ["--baseline", bpath, *extra]
        print(f"# journal drift: current vs baseline since {args.baseline_since}\n")
    else:
        print("# journal: anomalous entries in the captured window\n")

    env = anomalyx_scan(raw, extra)
    report(env, ctx)
    sys.exit(0 if env["exit"] == 0 else 1)


if __name__ == "__main__":
    main()
