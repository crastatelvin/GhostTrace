//! Windows capture module (plan Sections 6, 8; P2.1).
//!
//! Windows reparse-aware handle traversal (NtCreateFile with
//! FILE_FLAG_OPEN_REPARSE_POINT, identity checks via volume file IDs) is
//! implemented in the Windows work track. The Unix path is the verified
//! baseline (`unix.rs`); this module keeps the walker surface
//! platform-uniform and gives the Windows implementation a defined home.
//! It returns "unsupported" rather than pretending to work — honest
//! uncertainty over silent failure.

use crate::capture::walker::WalkOutcome;
use crate::capture::{CaptureRoot, CaptureSpec};
use crate::error::CoreError;

/// Windows traversal is not implemented yet; callers must see that clearly.
pub fn walk(_root: &CaptureRoot, _spec: &CaptureSpec) -> Result<WalkOutcome, CoreError> {
    Err(CoreError::Unsupported(
        "windows capture traversal is not implemented yet".into(),
    ))
}
