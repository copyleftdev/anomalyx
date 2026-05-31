# Input & normalization

> *"Given any corpus of information regardless of its format, we'll normalize
> it."*

anomalyx meets your data where it already lives. Every supported format —
whether a packet capture, a SIEM event stream, a Kubernetes manifest, or a
data-lake file — is lowered to one engine-independent record model, a
`RecordSet` of named, typed columns, and the detectors only ever see that. The
contract stays stable while the backend underneath it changes.

## Supported formats

**32 built-in parsers** across five domains. Each is an independent plugin
(`crates/ax-normalize/src/parsers/`); adding one doesn't touch the others.

### Tabular & structured data

| Format | Extensions | Notes |
|---|---|---|
| CSV / TSV | `.csv`, `.tsv`, `.tab` | lean deterministic reader |
| NDJSON / JSON | `.ndjson`, `.jsonl`, `.json` | array, object, or one-record-per-line |
| YAML | `.yaml`, `.yml` | Kubernetes / CI manifests; multi-document |
| TOML / INI | `.toml`, `.ini`, `.cfg`, `.conf` | config drift via `struct.schema` |
| XML | `.xml`, `.nessus` | Nessus/OpenVAS, SOAP; repeated element → rows |

### Columnar, data-lake & databases

| Format | Extensions | Backend |
|---|---|---|
| Parquet | `.parquet`, `.pq` | Polars / Arrow |
| Arrow IPC | `.arrow`, `.ipc`, `.feather` | Polars / Arrow |
| Avro | `.avro` | `apache-avro` |
| ORC | `.orc` | `orc-rust` → Arrow |
| Excel / ODS | `.xlsx`, `.xls`, `.xlsb`, `.ods` | `calamine` (first sheet) |
| SQLite | `.db`, `.sqlite`, `.sqlite3`, `.db3` | `rusqlite` (first table, in-memory deserialize) |

### Logs & observability

| Format | Detected by | Anomaly angle |
|---|---|---|
| logfmt | `key=value` shape | structured app logs |
| Web access logs (Combined/Common) | `[time] "request" status` | status-mix `dist`, latency `point`, bursts `coll` |
| syslog (RFC 3164 / 5424) | `<PRI>` header | event-rate `dist`, off-hours `contextual` |
| systemd journal | `journalctl -o json` | event-rate `cadence`/`coll`, rare-unit `dist` |
| Prometheus / OpenMetrics | exposition lines | per-series `point` spikes, `dist` drift |
| OpenTelemetry (OTLP/JSON) | `resourceSpans` | span-duration `point`, error-rate `dist`, emit `cadence` |

### Security telemetry

| Format | Detected by | Anomaly angle |
|---|---|---|
| Zeek (`conn.log` family) | `#separator` header | connection analytics |
| CEF / LEEF | `CEF:` / `LEEF:` prefix | signature/category mix shift via `dist.chi2` |
| auditd | `msg=audit(` | exec/syscall mix `dist`, bursty activity `coll` |
| EVTX (Windows Event Log) | `ElfFile` magic | rare event-ID `point`, logon `dist`, off-hours `contextual` |
| Suricata/Zeek EVE | `event_type` + `timestamp` | alert-type drift via `dist.chi2`; new classes surface |
| osquery results | `hostIdentifier` + `columns`/`snapshot` | fleet-posture drift via `structural`/`dist` |
| AWS CloudTrail | `Records[].eventName` | off-hours `contextual`/`cadence`, rare-API `dist` |

### Network

| Format | Detected by | Anomaly angle |
|---|---|---|
| PCAP / PCAPNG | libpcap / SHB magic | **beaconing/C2 via `cadence`** on inter-arrival times |
| NetFlow / IPFIX (nfdump CSV) | nfdump header | exfil via `mv.mahalanobis` on (bytes, packets, duration) |
| AWS VPC Flow Logs | `srcaddr dstaddr dstport` header | same flow anomalies, zero new infra |
| DNS query logs (dnsmasq) | `query[TYPE] … from` | DGA/exfil via `point` on name **entropy/length** + `cadence` |

Several parsers compute the features the detectors want rather than just
extracting fields — DNS query-name Shannon entropy and length, flow `duration`
(`end - start`), span `durationNanos`, normalized epoch timestamps — and rename
cryptic source fields to a canonical schema (e.g. nfdump `ibyt`→`bytes`,
`td`→`duration`).

## Resolution

Format is resolved by **file extension first**, then by **content sniff** —
binary magic numbers (`PAR1`, `ORC`, `SQLite format 3\0`, …) are checked at high
confidence, then distinctive text signatures, then a CSV last-resort fallback.
Resolution is deterministic: the highest-confidence match wins, ties break by
registration order. An unrecognized stream is an explicit error, never a silent
guess.

Several formats deliberately claim **no extension** (Zeek, syslog content,
journald, EVE, osquery, auditd, DNS, NetFlow, VPC) because their files are
generically `*.log`/`*.json`; pipe them on stdin and the content signature
routes them.

## Feature flags & the lean build

The binary and heavyweight parsers sit behind **default-on feature flags**, so a
default build reads everything but a `--no-default-features` build is a lean,
text-only normalizer with no binary dependencies:

| Feature | Parsers |
|---|---|
| `polars` | Parquet, Arrow IPC |
| `evtx` | EVTX |
| `pcap` | PCAP / PCAPNG |
| `xlsx` | Excel / ODS |
| `sqlite` | SQLite |
| `datalake` | Avro, ORC |

## The record model

A `RecordSet` is named columns of equal length, each with an inferred type:
`Int`, `Float`, `Bool`, `Str`, `Unknown`, or `Mixed` (conflicting concrete types
— itself a structural signal). Values collapse into a small closed set, and
**absence is explicit**: a missing cell is `Null`, never a sentinel `0.0` that
would skew a mean.

```text
amount,tier        →   column "amount": Int   [10, 11, 9, …]
10,a                   column "tier":   Str   ["a", "b", "c", …]
11,b
```

Binary and library-backed formats live entirely behind this boundary: a Polars
`DataFrame`, an Arrow `RecordBatch`, a calamine sheet, or a SQLite row is
converted to a `RecordSet` (integers fold to `i64`, floats to `f64` with
non-finite → `Null`, unsupported logical types preserved as their string form),
so no library type ever reaches a detector. Text formats touch none of it.
