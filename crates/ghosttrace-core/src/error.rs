//! Shared error categories (plan Sections 5, 9). Front ends map these to
//! actionable messages; the machine codes are stable and safe to log.

use std::fmt;

/// Every failure path in GhostTrace is one of these categories. The `code()`
/// values are the stable machine codes used in diagnostics and CLI output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// The request was malformed or semantically invalid before any work.
    InvalidInput(String),
    /// The format or version is not supported by this build.
    Unsupported(String),
    /// Permission or access failure touching evidence or the case store.
    Permission(String),
    /// The source changed underneath a read/verify step.
    InputChanged,
    /// Stored evidence did not match its recorded integrity state.
    CorruptEvidence,
    /// Storage layer failure (I/O, SQLite, full disk).
    Storage(String),
    /// The operation was cancelled by the user.
    Cancelled,
    /// A configured resource limit was reached.
    ResourceLimit,
    /// The case schema is incompatible with this build.
    SchemaIncompatible(String),
    /// Digest or signature verification failed (bytes differ from the record).
    IntegrityMismatch,
    /// Unexpected internal condition; never used for known input problems.
    Internal(String),
}

impl CoreError {
    /// Stable machine code for diagnostics and CLI exit mapping.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::InvalidInput(_) => "invalid_request",
            CoreError::Unsupported(_) => "unsupported_format",
            CoreError::Permission(_) => "permission",
            CoreError::InputChanged => "input_changed",
            CoreError::CorruptEvidence => "corrupt_evidence",
            CoreError::Storage(_) => "storage",
            CoreError::Cancelled => "cancelled",
            CoreError::ResourceLimit => "resource_limit",
            CoreError::SchemaIncompatible(_) => "schema_incompatible",
            CoreError::IntegrityMismatch => "integrity_mismatch",
            CoreError::Internal(_) => "internal_error",
        }
    }

    /// Human-facing detail, never containing raw evidence values.
    pub fn detail(&self) -> &str {
        match self {
            CoreError::InvalidInput(detail)
            | CoreError::Unsupported(detail)
            | CoreError::Permission(detail)
            | CoreError::Storage(detail)
            | CoreError::SchemaIncompatible(detail)
            | CoreError::Internal(detail) => detail,
            _ => "",
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())?;
        let detail = self.detail();
        if !detail.is_empty() {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CoreError {}

pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_and_distinct() {
        let codes = [
            CoreError::Cancelled.code(),
            CoreError::InputChanged.code(),
            CoreError::IntegrityMismatch.code(),
            CoreError::InvalidInput("x".into()).code(),
        ];
        assert_eq!(codes[0], "cancelled");
        assert_eq!(codes[1], "input_changed");
        assert_eq!(codes[2], "integrity_mismatch");
        assert_eq!(codes[3], "invalid_request");
    }

    #[test]
    fn display_never_leaks_hidden_state() {
        let error = CoreError::InvalidInput("field count 3".into());
        assert_eq!(error.to_string(), "invalid_request: field count 3");
    }
}
