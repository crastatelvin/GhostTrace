//! Streaming SHA-256 over exact captured bytes (plan Sections 5, 8; P2.2).
//!
//! Memory use is one fixed buffer, never proportional to file size. The
//! cancellation flag is checked between reads: a cancelled or failed read
//! returns an error and **no digest**, so an interrupted capture can never be
//! reported as a verified full-content hash.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use crate::error::{CoreError, CoreResult};

/// The single hashing/copy buffer. Bounded by design (plan Section 9).
pub const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// A full-content digest and the exact number of bytes it covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDigest {
    pub byte_length: u64,
    pub sha256: [u8; 32],
}

impl StreamDigest {
    pub fn hex(&self) -> String {
        sha256_hex(&self.sha256)
    }
}

/// Lowercase hex, the interchange form used by manifests and reports.
pub fn sha256_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Short lowercase hex digest of an identity string. Used for derived row
/// identifiers (events, entities) where the input is structured and the output
/// only needs to be stable and collision-resistant, never a content proof.
pub fn identity_hex(input: &str, chars: usize) -> String {
    let digest: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    sha256_hex(&digest)[..chars.min(64)].to_string()
}

/// Hash everything `reader` yields. Cancellation is honoured between reads;
/// the caller receives `Cancelled` and no digest.
pub fn digest_reader(reader: &mut impl Read, cancelled: &AtomicBool) -> CoreResult<StreamDigest> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    let mut total: u64 = 0;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled);
        }
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(CoreError::Storage(format!("hash read: {error}"))),
        };
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok(StreamDigest {
        byte_length: total,
        sha256: hasher.finalize().into(),
    })
}

/// Hash a stored file (verification of a captured copy). Errors are failures,
/// never an empty/short successful digest.
pub fn digest_file(path: &Path) -> CoreResult<StreamDigest> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| CoreError::Storage(format!("hash open: {error}")))?;
    let never = AtomicBool::new(false);
    digest_reader(&mut file, &never)
}

/// Verify a stored copy against its recorded digest. A length difference is a
/// mismatch even before hashing; differing bytes are `IntegrityMismatch`.
pub fn verify_file(path: &Path, expected: &StreamDigest) -> CoreResult<()> {
    let actual = digest_file(path)?;
    if actual == *expected {
        Ok(())
    } else {
        Err(CoreError::IntegrityMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: &[u8]) -> StreamDigest {
        let never = AtomicBool::new(false);
        digest_reader(&mut &bytes[..], &never).unwrap()
    }

    #[test]
    fn known_vectors() {
        // FIPS 180-4 / RFC 6234 well-known values.
        assert_eq!(
            digest(b"").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest(b"abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(digest(b"abc").byte_length, 3);
    }

    #[test]
    fn cancellation_yields_no_digest() {
        let cancelled = AtomicBool::new(true);
        let error = digest_reader(&mut &b"abc"[..], &cancelled).unwrap_err();
        assert_eq!(error.code(), "cancelled");
    }
}
