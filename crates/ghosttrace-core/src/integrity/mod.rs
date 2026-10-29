//! Integrity primitives: streaming hashing, the acquisition manifest, encrypted
//! signing keys, and detached signatures (plan Sections 5, 8, 12; P2.2, P9.1).
//!
//! Rule: a digest is only ever produced together with the exact bytes it
//! covered. Cancellation and read errors return no digest at all, so a partial
//! read can never be mistaken for a verified full-content hash.

pub mod hash;
pub mod keys;
pub mod manifest;
pub mod signature;
