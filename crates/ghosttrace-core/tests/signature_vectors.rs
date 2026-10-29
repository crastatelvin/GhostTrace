//! P9.1: Ed25519 known vectors and the exact domain-separated manifest
//! message. A signature must cover the bytes we define, not "some JSON".

use ed25519_dalek::{Signer, SigningKey, Verifier};
use ghosttrace_core::integrity::keys::{generate_key_file, hex, load_key_file};
use ghosttrace_core::integrity::signature::{
    SIGNED_DOMAIN, SignatureEnvelope, manifest_digest, signing_message,
};

/// RFC 8032 §7.1 TEST 1 secret key.
const RFC8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The exact manifest bytes used for the independent known-answer signature.
const VECTOR_MANIFEST: &[u8] = b"{\"format\":\"ghosttrace-manifest/1\"}\n";
const VECTOR_PASSPHRASE: &[u8] = b"correct horse battery staple";

#[test]
fn rfc8032_test_vector_1_holds() {
    let key = SigningKey::from_bytes(&RFC8032_SECRET);
    assert_eq!(
        hex(&key.verifying_key().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let signature = key.sign(b"");
    assert_eq!(
        hex(&signature.to_bytes()),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    key.verifying_key()
        .verify(b"", &signature)
        .expect("verifies");
}

#[test]
fn the_signed_message_is_the_domain_then_the_digest() {
    let digest = manifest_digest(VECTOR_MANIFEST);
    assert_eq!(
        hex(&digest),
        "ab5cb920b2bcd027d0ae787f2b56beb8afdc4dbb9d723c18327972cf1db1d40f"
    );
    let message = signing_message(&digest);
    assert_eq!(message.len(), SIGNED_DOMAIN.len() + 1 + 32);
    assert_eq!(&message[..SIGNED_DOMAIN.len()], SIGNED_DOMAIN);
    assert_eq!(message[SIGNED_DOMAIN.len()], 0);
    assert_eq!(&message[SIGNED_DOMAIN.len() + 1..], &digest);
}

#[test]
fn an_independent_implementation_agrees_on_the_signed_message() {
    // Signature produced by `openssl pkeyutl -sign -rawin` with the RFC 8032
    // key over `b"GhostTrace manifest v1\0" || sha256(VECTOR_MANIFEST)`.
    let key = SigningKey::from_bytes(&RFC8032_SECRET);
    let signature = key.sign(&signing_message(&manifest_digest(VECTOR_MANIFEST)));
    assert_eq!(
        hex(&signature.to_bytes()),
        "b335b161a1bf6f636b84a6b3acc34669f6d0d5ad2d813c5908b82f193128dc6f7c3498cc8a70012c308f2a89d4854393ebbdd06d045be4e7519fd0e832c44508"
    );
}

#[test]
fn a_signature_covers_exact_bytes_and_rejects_every_byte_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("key.pem");
    generate_key_file(&path, VECTOR_PASSPHRASE).expect("key");
    let key = load_key_file(&path, VECTOR_PASSPHRASE).expect("unlock");

    let manifest = b"{\n  \"format\": \"ghosttrace-manifest/1\"\n}\n";
    let envelope = SignatureEnvelope::sign(manifest, &key);
    envelope.check(manifest).expect("valid");

    // Whitespace, entry, and digest changes are all different bytes.
    for tampered in [
        b"{\n  \"format\": \"ghosttrace-manifest/1\"}\n".as_slice(),
        b"{\n  \"format\": \"ghosttrace-manifest/2\"\n}\n".as_slice(),
        b"{\n  \"format\": \"ghosttrace-manifest/1\", \"x\": 1\n}\n".as_slice(),
        b"".as_slice(),
    ] {
        let check = envelope.check(tampered).expect("shape is still valid");
        assert!(!check.signature_valid, "tampered bytes verified");
        assert!(!check.manifest_digest_matches);
    }
}

#[test]
fn the_envelope_round_trips_without_embedding_the_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("key.pem");
    generate_key_file(&path, VECTOR_PASSPHRASE).expect("key");
    let key = load_key_file(&path, VECTOR_PASSPHRASE).expect("unlock");
    let envelope = SignatureEnvelope::sign(VECTOR_MANIFEST, &key);
    let text = envelope.to_json().expect("json");
    assert!(text.ends_with("}\n"));
    assert!(!text.contains("ghosttrace-manifest/1"), "{text}");
    let parsed: SignatureEnvelope = serde_json::from_str(&text).expect("parse");
    assert_eq!(parsed, envelope);
    assert_eq!(envelope.algorithm, "ed25519");
    assert_eq!(envelope.public_key, key.identity().public_key);
    assert_eq!(envelope.key_fingerprint, key.identity().key_fingerprint);
}
