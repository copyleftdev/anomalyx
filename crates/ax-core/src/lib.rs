//! # ax-core — the anomalyx contract
//!
//! This crate is the *executable contract* the [article][1] argues for: the
//! typed record model every input collapses into, the anomaly taxonomy, the
//! deterministic reductions detectors are built on, and the `tq1` output
//! envelope. It deliberately depends on nothing heavy (no Polars, no math
//! crates) so the contract stays engine-independent and the mutation-test gate
//! stays fast.
//!
//! Design commitments, straight from the article:
//! - **Determinism is UX**: see [`det`] — every reduction is order-independent.
//! - **Honest absence**: [`value::Value::Null`] never becomes a `0.0`;
//!   detectors that can't run are recorded in [`envelope::Absence`].
//! - **Handle-based evidence**: compact [`finding::Finding`]s carry stable
//!   [`finding::Handle`]s that `explain` resolves on demand.
//! - **Versioned protocol**: [`envelope::PROTOCOL`] and committed
//!   [`envelope::ExitCode`]s.
//!
//! [1]: https://dev.to/copyleftdev/ai-tools-need-contracts-not-prompts-5ca3

pub mod det;
pub mod dict;
pub mod envelope;
pub mod error;
pub mod finding;
pub mod record;
pub mod roles;
pub mod value;

pub use error::{AxError, Result};
pub use finding::{AnomalyClass, Finding, Handle, Severity};
pub use record::{Column, RecordSet};
pub use roles::{ColumnRole, Role};
pub use value::{ColType, Value};
