# The four-verb contract

anomalyx exposes a deliberately small, discoverable surface. An agent can answer
"what is this, what does it produce, what did it find, and why" with four verbs.

```text
anomalyx describe                                     Protocol metadata
anomalyx schema                                       JSON Schema of scan output
anomalyx scan [--baseline B] [--period N] [--cadence COL] [PATH]
anomalyx explain <HANDLE> [--baseline B] [--period N] [--cadence COL] [PATH]
```

Input is a `PATH` or stdin (`-`). **Exit codes are part of the contract:**

| code | meaning |
|------|---------|
| `0`  | clean — no anomalies |
| `1`  | anomalies found |
| `2`  | tool error (bad input, unresolved handle, …) |

## `describe` — what this is

Emits protocol metadata: the supported input formats, the registered detectors,
the anomaly classes, the exit-code semantics, and the current deterministic
config fingerprint. Everything is derived from the same registries `scan` uses,
so the description can't drift from behavior.

## `schema` — the shape of the output

Emits a JSON Schema (draft 2020-12) pinning the `tq1` envelope. Validate against
it instead of reverse-engineering field names. See [The tq1 envelope](./envelope.md).

## `scan` — normalize, then detect

Reads the corpus, normalizes it to the internal record model, runs every
detector, and prints one dense `tq1` envelope.

```console
$ anomalyx scan sales.csv
{"protocol":"anomalyx/tq1", ... ,"exit":1}
```

## `explain` — drill into a finding

Findings carry a stable **handle** (e.g. `cell:amount:8`, `dist:score`,
`row:42`, `range:ts:20:40`). `explain` resolves one back to its underlying
evidence, and re-attaches any findings pointing at it. An unresolvable handle
fails cleanly with exit `2` — never a fabricated hit.

```console
$ anomalyx explain cell:amount:8 sales.csv
{"protocol":"anomalyx/tq1","handle":"cell:amount:8",
 "evidence":{"kind":"cell","column":"amount","row":8,"value":{"t":"int","v":9999}},
 "findings":[{"detector":"point.modz","class":"point","confidence":1.0, ... }]}
```
