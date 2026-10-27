//! Integrity primitives: streaming hashing and the acquisition manifest
//! (plan Sections 5, 8; P2.2).
//!
//! Rule: a digest is only ever produced together with the exact bytes it
//! covered. Cancellation and read errors return no digest at all, so a partial
//! read can never be mistaken for a verified full-content hash.

pub mod hash;
pub mod manifest;
