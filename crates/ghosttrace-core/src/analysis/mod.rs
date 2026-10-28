//! Derived analysis over captured evidence (plan Sections 7, 10).
//!
//! Analysis reads the case through the shared reader; it never mutates source
//! evidence and never claims more than the recorded observations support.

pub mod annotations;
pub mod correlate;
pub mod diff;
pub mod entities;
pub mod rules;
pub mod views;
