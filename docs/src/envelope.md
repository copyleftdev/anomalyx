# The tq1 envelope

`scan` emits a single JSON object — the `tq1` envelope. It is *dense and typed*,
not pretty text: a dictionary-pinned string table with findings encoded as
fixed-shape rows that reference it. Changing any field is an API change and is
guarded by a contract test. Run `anomalyx schema` for the machine-readable
JSON Schema.

```json
{
  "protocol": "anomalyx/tq1",
  "config_version": "anomalyx-cfg/5;pt=3.5000;...",
  "source": "sales.csv",
  "format": "csv",
  "baseline": "last_week.csv",        // present only in --baseline mode
  "rows_scanned": 9,
  "dict": ["point.modz", "point", "cell:amount:8", "critical", "amount = 9999 …"],
  "columns": ["detector","class","handle","confidence","severity","score","reason"],
  "rows": [ [0, 1, 2, 1.0, 3, 4544.43, 4] ],
  "absent": [ {"detector":"dist.ks","reason":"no baseline provided …"} ],
  "summary": { "total": 1, "max_severity": "critical", "by_class": [ … ] },
  "exit": 1
}
```

## Fields

- **`protocol`** — `"anomalyx/tq1"`. Bumps on any breaking envelope change.
- **`config_version`** — a fingerprint of every setting that affects output.
  Same input + same fingerprint ⇒ byte-identical output. Lets you tell "the data
  changed" from "the configuration changed."
- **`dict`** — the string table. Every repeated string (detector ids, class
  tokens, handles, severities, reasons) appears once here; rows reference it by
  index. No magic constants.
- **`columns`** — the fixed column order of each dense finding row.
- **`rows`** — one array per finding, aligned to `columns`:
  `[detector_idx, class_idx, handle_idx, confidence, severity_idx, score, reason_idx]`.
  `confidence` is **calibrated to one scale across every detector**: a logistic of
  how far the detector's statistic sits past its firing threshold, measured
  relatively (so units cancel) — `0.5` at the threshold, rising toward `1.0`. A
  finding "2× past threshold" earns the same confidence whether it came from a
  modified z-score, a KS p-value, a PSI, or a cadence CV, so `severity` (derived
  from confidence) ranks findings from different detectors on one scale. `score`
  is the detector's raw statistic (uncalibrated), for drill-down.
- **`absent`** — detectors that declined to run, each with a machine-readable
  reason. See [honest absence](./determinism.md).
- **`summary`** — total count, max severity, and per-class counts for at-a-glance
  triage.
- **`exit`** — the committed exit code, mirrored into the envelope.

## Handles

Findings are compact but **drill-able**. Each carries a stable handle whose
canonical string is consistent across runs, so an agent can cache it and later
`explain` it:

| Handle | Form | Used by |
|---|---|---|
| column | `col:<name>` | structural |
| cell | `cell:<column>:<row>` | point |
| range | `range:<column>:<start>:<end>` | collective |
| dist | `dist:<column>` | distributional |
| row | `row:<n>` | multivariate |

Findings are sorted deterministically (severity desc, then class, handle,
detector), so the envelope is stable regardless of the order detectors ran.
