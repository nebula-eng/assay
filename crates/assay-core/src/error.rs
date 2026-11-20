//! Error types for the Assay analysis engine.
//!
//! Every fallible operation in this crate returns [`Result<T>`]. Parsing errors
//! are *never* fatal to an analysis run: the caller records them as
//! [`crate::report::Diagnostic`] entries and keeps whatever structure was
//! recovered before the failure. Attackers deliberately craft malformed headers
//! to break analysers, so a parser that gives up entirely is a parser that can
//! be blinded.

use std::fmt;
use std::path::PathBuf;

/// Convenient alias used throughout the crate.
pub type Result<T> = std::result::Result<T, AssayError>;

/// Everything that can go wrong while analysing an artefact.
#[derive(Debug, thiserror::Error)]
pub enum AssayError {
    /// The file could not be read from disk.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The byte stream ended before a structure could be decoded.
    #[error(
        "truncated {what} at offset {offset:#x}: needed {needed} bytes, {available} available"
    )]
    Truncated {
        /// Human readable name of the structure being decoded.
        what: &'static str,
        /// Absolute file offset where decoding was attempted.
        offset: u64,
        /// Bytes the structure required.
        needed: usize,
        /// Bytes actually left in the buffer.
        available: usize,
    },

    /// A structure was present but its contents violate the format spec.
    #[error("malformed {what} at offset {offset:#x}: {detail}")]
    Malformed {
        /// Structure name.
        what: &'static str,
        /// Absolute file offset.
        offset: u64,
        /// What specifically is wrong.
        detail: String,
    },

    /// The container is well formed but uses a feature this build cannot decode.
    #[error("unsupported {what}: {detail}")]
    Unsupported {
        /// Feature area, e.g. `"elf"` or `"compression"`.
        what: &'static str,
        /// Explanation, ideally with the offending value.
        detail: String,
    },

    /// The input does not look like any format Assay understands.
    #[error("unrecognised container format (first bytes: {magic})")]
    UnknownFormat {
        /// Hex rendering of the first bytes, for user feedback.
        magic: String,
    },

    /// A rule file failed to load.
    #[error("rule {id} is invalid: {detail}")]
    InvalidRule {
        /// Rule identifier, or `<unnamed>` when the id itself is missing.
        id: String,
        /// Validation failure.
        detail: String,
    },
}

impl AssayError {
    /// Build an [`AssayError::Malformed`] without repeating the field names.
    pub(crate) fn malformed(what: &'static str, offset: u64, detail: impl fmt::Display) -> Self {
        AssayError::Malformed {
            what,
            offset,
            detail: detail.to_string(),
        }
    }

    /// Build an [`AssayError::Unsupported`].
    pub(crate) fn unsupported(what: &'static str, detail: impl fmt::Display) -> Self {
        AssayError::Unsupported {
            what,
            detail: detail.to_string(),
        }
    }

    /// A short machine-readable category, used as the `kind` field in diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            AssayError::Io { .. } => "io",
            AssayError::Truncated { .. } => "truncated",
            AssayError::Malformed { .. } => "malformed",
            AssayError::Unsupported { .. } => "unsupported",
            AssayError::UnknownFormat { .. } => "unknown-format",
            AssayError::InvalidRule { .. } => "invalid-rule",
        }
    }
}
