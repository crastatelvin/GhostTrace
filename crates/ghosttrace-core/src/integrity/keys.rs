//! Encrypted Ed25519 key files (plan Section 12; P9.1).
//!
//! Keys are standard encrypted PKCS#8 (PBES2 + scrypt by default), never a
//! home-grown format. The private key exists in memory only while a signature
//! is being made; it is zeroized on drop and never enters the case store.
//!
//! The loader refuses to decrypt key files whose KDF parameters or cipher
//! exceed the bounds below, so a hostile key file cannot turn a prompt into an
//! unbounded memory or CPU commitment.

use std::io::Write;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use pkcs8::pkcs5::EncryptionScheme;
use pkcs8::pkcs5::pbes2::{Kdf, Pbkdf2Prf};
use pkcs8::{EncodePrivateKey, EncryptedPrivateKeyInfoRef, LineEnding, PrivateKeyInfoRef};
use zeroize::Zeroize;

use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::sha256_hex;

/// PEM label for an encrypted PKCS#8 private key (RFC 5958).
pub const KEY_PEM_LABEL: &str = "ENCRYPTED PRIVATE KEY";

/// A passphrase shorter than this protects nothing and is refused.
pub const MIN_PASSPHRASE_BYTES: usize = 8;
/// Upper bound so a key file cannot turn into a self-inflicted KDF DoS.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
/// scrypt: at most 2^16 (64 MiB with r=8) and small r/p.
const MAX_SCRYPT_COST: u64 = 1 << 16;
const MAX_SCRYPT_BLOCK_SIZE: u16 = 16;
const MAX_SCRYPT_PARALLELIZATION: u16 = 4;
/// PBKDF2: far above the OWASP 600k default, far below a hang.
const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

/// Public identity of a key. Safe to display, log, and share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdentity {
    /// Lowercase hex of the 32-byte Ed25519 verifying key.
    pub public_key: String,
    /// Lowercase hex SHA-256 of the verifying key bytes.
    pub key_fingerprint: String,
}

/// A decrypted signing key. Zeroized on drop by `ed25519-dalek`.
pub struct UnlockedKey {
    signing: SigningKey,
}

impl std::fmt::Debug for UnlockedKey {
    /// Debug never prints secret material; only the public fingerprint.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnlockedKey")
            .field("key_fingerprint", &self.identity().key_fingerprint)
            .finish_non_exhaustive()
    }
}

impl UnlockedKey {
    /// The public identity of this key.
    pub fn identity(&self) -> KeyIdentity {
        let public = self.signing.verifying_key().to_bytes();
        KeyIdentity {
            public_key: hex(&public),
            key_fingerprint: fingerprint(&public),
        }
    }

    /// Sign one exact message. Ed25519 is deterministic.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// The 32-byte verifying key, for callers that verify immediately.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

/// Generate a new Ed25519 key from OS randomness and write it encrypted.
///
/// The destination is created exclusively (`create_new`) with mode `0600`; an
/// existing file is never overwritten. The path may not be inside a case.
pub fn generate_key_file(path: &Path, passphrase: &[u8]) -> CoreResult<KeyIdentity> {
    check_passphrase(passphrase)?;
    refuse_case_store(path)?;
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| CoreError::Internal(format!("os randomness: {error}")))?;
    let signing = SigningKey::from_bytes(&secret);
    secret.zeroize();
    write_key_file(path, &signing, passphrase)?;
    let public = signing.verifying_key().to_bytes();
    Ok(KeyIdentity {
        public_key: hex(&public),
        key_fingerprint: fingerprint(&public),
    })
}

/// Load and decrypt a key file.
pub fn load_key_file(path: &Path, passphrase: &[u8]) -> CoreResult<UnlockedKey> {
    check_passphrase(passphrase)?;
    let bytes = read_private_file(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CoreError::Unsupported("the key file is not UTF-8 PEM text".into()))?;
    let (label, document) = pkcs8::SecretDocument::from_pem(text)
        .map_err(|_| CoreError::Unsupported("the key file is not a PEM document".into()))?;
    if label != KEY_PEM_LABEL {
        return Err(CoreError::Unsupported(format!(
            "the key file is {label:?}, not an encrypted PKCS#8 private key"
        )));
    }
    let info = EncryptedPrivateKeyInfoRef::try_from(document.as_bytes())
        .map_err(|_| CoreError::Unsupported("the encrypted key structure is malformed".into()))?;
    check_encryption(&info.encryption_algorithm)?;
    let decrypted = info.decrypt(passphrase).map_err(|_| {
        CoreError::InvalidInput("the key passphrase does not decrypt this key file".into())
    })?;
    let private = PrivateKeyInfoRef::try_from(decrypted.as_bytes())
        .map_err(|_| CoreError::Unsupported("the decrypted key structure is malformed".into()))?;
    let signing = SigningKey::try_from(private)
        .map_err(|_| CoreError::Unsupported("the key is not a valid Ed25519 private key".into()))?;
    Ok(UnlockedKey { signing })
}

/// Re-encrypt an existing encrypted PKCS#8 key into a new key file.
pub fn import_key_file(
    source: &Path,
    destination: &Path,
    source_passphrase: &[u8],
    destination_passphrase: &[u8],
) -> CoreResult<KeyIdentity> {
    check_passphrase(destination_passphrase)?;
    refuse_case_store(destination)?;
    if same_path(source, destination) {
        return Err(CoreError::InvalidInput(
            "the import destination must differ from the source key file".into(),
        ));
    }
    let key = load_key_file(source, source_passphrase)?;
    write_key_file(destination, &key.signing, destination_passphrase)?;
    Ok(key.identity())
}

/// Write a private key file. Refuses to overwrite and uses `0600` on Unix.
fn write_key_file(path: &Path, signing: &SigningKey, passphrase: &[u8]) -> CoreResult<()> {
    let pem = signing
        .to_pkcs8_encrypted_pem(passphrase, LineEnding::LF)
        .map_err(|error| CoreError::Internal(format!("key encryption: {error}")))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent)
        .map_err(|error| CoreError::Storage(format!("key directory: {error}")))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CoreError::InvalidInput(format!(
                "a file already exists at {}; a key is never overwritten",
                path.display()
            ))
        } else {
            CoreError::Storage(format!("key create: {error}"))
        }
    })?;
    file.write_all(pem.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            let _ = std::fs::remove_file(path);
            CoreError::Storage(format!("key write: {error}"))
        })?;
    Ok(())
}

/// Read a key file with ownership, mode, type, and size checks.
fn read_private_file(path: &Path) -> CoreResult<zeroize::Zeroizing<Vec<u8>>> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| CoreError::Storage(format!("key file: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(CoreError::Permission(
            "the key file must not be a symlink".into(),
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(CoreError::Permission(
            "the key path is not a regular file".into(),
        ));
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(CoreError::Unsupported(format!(
            "the key file is larger than {MAX_KEY_FILE_BYTES} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(CoreError::Permission(format!(
                "the key file {} is readable by group or others; run chmod 600 on it",
                path.display()
            )));
        }
        let euid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != euid {
            return Err(CoreError::Permission(format!(
                "the key file {} is owned by another user",
                path.display()
            )));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse a symlink swapped in after the metadata check.
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| CoreError::Permission(format!("key open: {error}")))?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .map_err(|error| CoreError::Storage(format!("key read: {error}")))?;
    Ok(bytes)
}

/// Reject key paths inside a case directory. Keys never enter a case.
fn refuse_case_store(path: &Path) -> CoreResult<()> {
    let inside = path.components().any(|component| match component {
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| name.ends_with(".ghosttrace-case")),
        _ => false,
    });
    if inside {
        return Err(CoreError::InvalidInput(
            "a signing key may not be written inside a case directory".into(),
        ));
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => {
            let absolute = |path: &Path| -> PathBuf {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(path)
                }
            };
            absolute(left) == absolute(right)
        }
    }
}

fn check_passphrase(passphrase: &[u8]) -> CoreResult<()> {
    if passphrase.len() < MIN_PASSPHRASE_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "the passphrase must be at least {MIN_PASSPHRASE_BYTES} bytes"
        )));
    }
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "the passphrase is longer than {MAX_PASSPHRASE_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Accept only modern, bounded PBES2 parameters.
fn check_encryption(scheme: &EncryptionScheme) -> CoreResult<()> {
    let EncryptionScheme::Pbes2(params) = scheme else {
        return Err(CoreError::Unsupported(
            "the key file uses a legacy PBES1 scheme; insecure key encryption is refused".into(),
        ));
    };
    match &params.kdf {
        Kdf::Scrypt(scrypt) => {
            if scrypt.cost_parameter > MAX_SCRYPT_COST
                || scrypt.block_size > MAX_SCRYPT_BLOCK_SIZE
                || scrypt.parallelization > MAX_SCRYPT_PARALLELIZATION
            {
                return Err(CoreError::Unsupported(
                    "the key file's scrypt parameters exceed the accepted bounds".into(),
                ));
            }
        }
        Kdf::Pbkdf2(pbkdf2) => {
            if pbkdf2.iteration_count > MAX_PBKDF2_ITERATIONS {
                return Err(CoreError::Unsupported(
                    "the key file's PBKDF2 iteration count exceeds the accepted bound".into(),
                ));
            }
            if pbkdf2.prf != Pbkdf2Prf::HmacWithSha256 {
                return Err(CoreError::Unsupported(
                    "the key file's PBKDF2 PRF is not HMAC-SHA-256".into(),
                ));
            }
        }
        _ => {
            return Err(CoreError::Unsupported(
                "the key file's key-derivation function is not supported".into(),
            ));
        }
    }
    if !matches!(
        params.encryption,
        pkcs8::pkcs5::pbes2::EncryptionScheme::Aes256Cbc { .. }
    ) {
        return Err(CoreError::Unsupported(
            "the key file cipher is not AES-256-CBC".into(),
        ));
    }
    Ok(())
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Strict lowercase/uppercase hex decode into a fixed-size array.
pub fn unhex<const N: usize>(text: &str) -> CoreResult<[u8; N]> {
    if text.len() != N * 2 {
        return Err(CoreError::Unsupported(format!(
            "expected {} hex characters, found {}",
            N * 2,
            text.len()
        )));
    }
    let mut out = [0u8; N];
    let bytes = text.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&bytes[index * 2..index * 2 + 2])
            .map_err(|_| CoreError::Unsupported("malformed hex encoding".into()))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| CoreError::Unsupported("malformed hex encoding".into()))?;
    }
    Ok(out)
}

/// Key fingerprint: SHA-256 of the 32-byte verifying key, lowercase hex.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    sha256_hex(&hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::pkcs5::pbes1;
    use pkcs8::pkcs5::pbes2;

    fn scrypt_parameters() -> pbes2::Parameters {
        let params = pkcs8::pkcs5::scrypt::Params::new(14, 8, 1).expect("scrypt params");
        pbes2::Parameters::generate_scrypt_aes256cbc(params, &[7u8; 16], [9u8; 16])
            .expect("pbes2 parameters")
    }

    #[test]
    fn legacy_pbes1_is_refused() {
        let scheme = EncryptionScheme::Pbes1(pbes1::Algorithm {
            encryption: pbes1::EncryptionScheme::PbeWithMd5AndDesCbc,
            parameters: pbes1::Parameters {
                salt: [0u8; 8],
                iteration_count: 1000,
            },
        });
        let error = check_encryption(&scheme).expect_err("pbes1");
        assert!(error.detail().contains("PBES1"), "{error}");
    }

    #[test]
    fn aes_128_is_refused_but_aes_256_is_accepted() {
        let mut params = scrypt_parameters();
        check_encryption(&EncryptionScheme::Pbes2(params.clone())).expect("aes256");
        params.encryption = pbes2::EncryptionScheme::Aes128Cbc { iv: [0u8; 16] };
        let error = check_encryption(&EncryptionScheme::Pbes2(params)).expect_err("aes128");
        assert!(error.detail().contains("AES-256-CBC"), "{error}");
    }

    #[test]
    fn unbounded_scrypt_is_refused() {
        let mut params = scrypt_parameters();
        if let Kdf::Scrypt(scrypt) = &mut params.kdf {
            scrypt.cost_parameter = 1 << 30;
        }
        let error = check_encryption(&EncryptionScheme::Pbes2(params)).expect_err("huge");
        assert!(error.detail().contains("bounds"), "{error}");
    }

    #[test]
    fn unhex_is_strict() {
        assert_eq!(unhex::<1>("0a").unwrap(), [10]);
        assert!(unhex::<1>("0").is_err());
        assert!(unhex::<1>("0g").is_err());
        assert!(unhex::<1>("0A").is_ok());
    }
}
