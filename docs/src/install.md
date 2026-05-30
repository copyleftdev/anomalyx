# Install

## From crates.io

```console
cargo install anomalyx
```

This installs the `anomalyx` binary. It pulls in the library crates
(`anomalyx-core`, `anomalyx-normalize`, `anomalyx-detect`) automatically.

## From source

```console
git clone https://github.com/copyleftdev/anomalyx
cd anomalyx
cargo install --path crates/anomalyx
```

## Feature flags

Binary columnar formats (Parquet, Arrow IPC) are read through the Polars
backbone, behind the default-on `polars` feature of `anomalyx-normalize`. A
lean, text-only build drops that heavy dependency:

```console
# text formats only (CSV / TSV / NDJSON / JSON), no Polars
cargo build -p anomalyx-normalize --no-default-features
```

Without the feature, a Parquet/Arrow input fails cleanly with an explicit
"requires the 'polars' feature" error rather than misbehaving — honest absence
at the build level.

## Using the libraries

The detection engine is usable as a library. The crates.io packages are
namespaced (`anomalyx-*`) but expose conventional module names:

```toml
[dependencies]
anomalyx-core = "0.1"
anomalyx-detect = "0.1"
anomalyx-normalize = "0.1"
```

```rust,ignore
use ax_detect::{Registry, ScanContext, DetectConfig};

let rs = ax_normalize::normalize("data.csv", &bytes)?;
let report = Registry::default_set()
    .run(&ScanContext::single(&rs), &DetectConfig::default());
```
