//! P9.1: key files are standard encrypted PKCS#8, private by permissions, and
//! never leak their passphrase or plaintext key material.

use std::path::Path;

use ghosttrace_core::integrity::keys::{
    MAX_PASSPHRASE_BYTES, generate_key_file, import_key_file, load_key_file,
};
use pkcs8::EncryptedPrivateKeyInfoRef;
use pkcs8::pkcs5::EncryptionScheme;
use pkcs8::pkcs5::pbes2::{EncryptionScheme as Pbes2Cipher, Kdf};

const PASS: &[u8] = b"correct horse battery staple";

/// Files written by tests are not created with `0600`; make them private so
/// the permission check does not mask the failure under test.
#[cfg(unix)]
fn private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).expect("chmod");
}

#[cfg(not(unix))]
fn private(_path: &Path) {}

fn key(dir: &Path, name: &str, passphrase: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    generate_key_file(&path, passphrase).expect("generate");
    path
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("metadata").mode() & 0o777
}

#[test]
fn a_generated_key_is_encrypted_pbes2_scrypt_aes256_and_private() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = key(dir.path(), "signing.pem", PASS);
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(text.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    assert!(
        !text.contains(std::str::from_utf8(PASS).unwrap()),
        "the passphrase is not stored"
    );
    assert!(
        !text.to_ascii_lowercase().contains("ghosttrace"),
        "the key file is a standard PKCS#8 document, not a private format"
    );
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600, "group/other bits must be clear");

    let (label, document) = pkcs8::SecretDocument::from_pem(&text).expect("pem");
    assert_eq!(label, "ENCRYPTED PRIVATE KEY");
    let info = EncryptedPrivateKeyInfoRef::try_from(document.as_bytes()).expect("structure");
    let EncryptionScheme::Pbes2(params) = &info.encryption_algorithm else {
        panic!("not PBES2");
    };
    assert!(matches!(params.kdf, Kdf::Scrypt(_)), "recommended scrypt");
    assert!(
        matches!(params.encryption, Pbes2Cipher::Aes256Cbc { .. }),
        "AES-256-CBC"
    );

    let unlocked = load_key_file(&path, PASS).expect("unlock");
    let identity = unlocked.identity();
    assert_eq!(identity.public_key.len(), 64);
    assert_eq!(identity.key_fingerprint.len(), 64);
    assert_eq!(load_key_file(&path, PASS).unwrap().identity(), identity);
}

#[test]
fn a_wrong_passphrase_fails_without_echoing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = key(dir.path(), "signing.pem", PASS);
    let error = load_key_file(&path, b"definitely the wrong passphrase").expect_err("wrong pass");
    let text = error.to_string();
    assert!(text.contains("does not decrypt"), "{text}");
    assert!(!text.contains("definitely the wrong passphrase"), "{text}");
}

#[test]
fn weak_or_oversized_passphrases_are_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("signing.pem");
    for passphrase in [b"".as_slice(), b"short".as_slice()] {
        let error = generate_key_file(&path, passphrase).expect_err("short");
        assert!(error.to_string().contains("at least"), "{error}");
    }
    let huge = vec![b'a'; MAX_PASSPHRASE_BYTES + 1];
    let error = generate_key_file(&path, &huge).expect_err("huge");
    assert!(error.to_string().contains("longer than"), "{error}");
    assert!(!path.exists(), "a refused key is not written");
}

#[test]
fn an_existing_key_is_never_overwritten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = key(dir.path(), "signing.pem", PASS);
    let before = std::fs::read(&path).expect("read");
    let error = generate_key_file(&path, PASS).expect_err("exists");
    assert!(error.to_string().contains("already exists"), "{error}");
    assert_eq!(std::fs::read(&path).expect("read"), before);
}

#[test]
fn a_key_cannot_be_written_inside_a_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let case = dir.path().join("case.ghosttrace-case");
    std::fs::create_dir_all(&case).expect("case dir");
    let error = generate_key_file(&case.join("signing.pem"), PASS).expect_err("case");
    assert!(error.to_string().contains("case directory"), "{error}");
    assert!(!case.join("signing.pem").exists());
}

#[cfg(unix)]
#[test]
fn group_readable_keys_and_symlinks_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = key(dir.path(), "signing.pem", PASS);
    let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(&path, permissions).expect("chmod");
    let error = load_key_file(&path, PASS).expect_err("too open");
    assert!(error.to_string().contains("chmod 600"), "{error}");

    let link = dir.path().join("link.pem");
    symlink(&path, &link).expect("symlink");
    let error = load_key_file(&link, PASS).expect_err("symlink");
    assert!(error.to_string().contains("symlink"), "{error}");
}

#[test]
fn a_damaged_ciphertext_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = key(dir.path(), "signing.pem", PASS);
    let text = std::fs::read_to_string(&path).expect("read");
    // Flip one base64 character in the encrypted body.
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let body = lines
        .iter()
        .position(|line| line.starts_with("-----BEGIN"))
        .map(|index| index + 1)
        .expect("pem");
    let mut bytes = lines[body].clone().into_bytes();
    bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
    lines[body] = String::from_utf8(bytes).expect("ascii");
    std::fs::write(&path, lines.join("\n") + "\n").expect("write");
    private(&path);
    let error = load_key_file(&path, PASS).expect_err("damaged");
    assert!(
        error.to_string().contains("does not decrypt")
            || error.to_string().contains("malformed")
            || error.to_string().contains("PEM"),
        "{error}"
    );
}

#[test]
fn a_non_pem_file_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("not-a-key.pem");
    std::fs::write(&path, b"this is not a key\n").expect("write");
    private(&path);
    let error = load_key_file(&path, PASS).expect_err("not pem");
    assert!(error.to_string().contains("PEM"), "{error}");
}

#[test]
fn import_re_encrypts_the_same_key_under_a_new_passphrase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = key(dir.path(), "source.pem", PASS);
    let destination = dir.path().join("destination.pem");
    let identity =
        import_key_file(&source, &destination, PASS, b"a different passphrase").expect("import");
    assert_eq!(
        identity,
        load_key_file(&destination, b"a different passphrase")
            .expect("new pass")
            .identity()
    );
    assert!(load_key_file(&destination, PASS).is_err(), "old pass fails");
    assert_ne!(
        std::fs::read(&source).expect("source"),
        std::fs::read(&destination).expect("destination"),
        "the ciphertext is fresh, not copied"
    );
    let error = import_key_file(&source, &source, PASS, PASS).expect_err("same path");
    assert!(error.to_string().contains("must differ"), "{error}");
}
