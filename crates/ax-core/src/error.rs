//! Core error type. Detectors and normalizers surface failures here; the CLI
//! maps these to [`crate::envelope::ExitCode::Error`].

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AxError {
    #[error("unsupported or unrecognized input format: {0}")]
    UnknownFormat(String),

    #[error("failed to parse {format} input: {message}")]
    Parse { format: String, message: String },

    #[error("io error: {0}")]
    Io(String),

    #[error("malformed handle: {0}")]
    BadHandle(String),

    #[error("handle does not resolve against this corpus: {0}")]
    UnresolvedHandle(String),

    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, AxError>;
