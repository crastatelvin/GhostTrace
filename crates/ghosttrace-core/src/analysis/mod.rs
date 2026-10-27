//! Derived analysis over captured evidence (plan Sections 7, 10).
//!
//! Analysis reads the case through the shared reader; it never mutates source
//! evidence and never claims more than the recorded observations support.

pub mod diff;
