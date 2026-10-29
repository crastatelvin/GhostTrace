# Threat model

GhostTrace is a local-first forensic workbench. This document states the trust
boundaries it actually enforces, the adversarial inputs it is tested against,
and the limits it does not claim to cross. It is a working engineering
document, not a certification.

## Assets

| Asset | Why it matters | Protection |
|---|---|---|
| Source evidence | The thing under investigation; it must never change | Opened read-only, no-follow containment, captured bytes are immutable |
| Captured objects | The bytes a finding cites | Content-addressed by SHA-256, digest verified on read/verify/restore |
| Case database | Recorded observations, provenance, coverage | WAL, schema version + migration checksums, online backup |
| Signing keys | Prove who produced a manifest or package | Encrypted PKCS#8, `0600`, never inside a case, never logged |
| Reports and packages | Shared with other people | Atomic publication, explicit redaction, digest inventory |
| Case notes and paths | May contain personal or sensitive data | Never logged by default; redaction ledger records counts only |

## Trust boundaries

1. **Evidence bytes → parser.** EVTX, JSONL, journal exports, browser
   databases, and syslog are hostile input. Parsers are bounded (record count,
   record size, time and memory limits), run in-process only for non-record
   adapters, and run in an isolated worker for EVTX and journal exports. A
   parser failure is a recorded diagnostic, never a silent empty result.
2. **Captured path → filesystem.** Paths are native bytes/UTF-16, never
   normalized into a different identity. Capture uses descriptor-relative,
   no-follow traversal and records every gap (excluded, inaccessible, unstable,
   vanished, unsupported, unobserved) rather than claiming complete coverage.
3. **Case data → UI/CLI.** Recorded text is escaped for display; control and
   bidi characters are rendered visibly. ANSI escapes never reach a pipe. The
   GUI never queries SQLite from the render pass.
4. **Case → report/package.** Reports are built from recorded rows only.
   Reports and packages are published atomically and never overwrite an
   existing directory. A package inventory is verified against exact bytes.
5. **Signer → verifier.** A signature proves possession of a key over exact
   bytes. It does not prove the key belongs to the expected person: signature
   validity and key trust are separate, reported statuses. A valid signature
   from an untrusted key is accepted and labelled untrusted.
6. **Backup → restore.** A backup is untrusted until its inventory, every
   digest, `PRAGMA integrity_check`, the schema version, the case id, and every
   object reference have been verified in a private staging directory.

## Adversarial inputs covered by tests

| Input class | Test |
|---|---|
| Arbitrary integers/epochs/units at the time boundary | `crates/ghosttrace-core/tests/fuzz_targets.rs` |
| Arbitrary native-path interchange encodings | `fuzz_targets.rs`, `native_paths.rs` |
| Arbitrary manifest text, duplicate keys | `fuzz_targets.rs`, `manifest_trust.rs` |
| Arbitrary text projected to CSV/display | `fuzz_targets.rs`, `csv_safety.rs`, `terminal_safety.rs` |
| Arbitrary worker frames, oversize/truncated frames | `fuzz_targets.rs`, `worker_protocol.rs`, `worker_crash.rs` |
| Truncated/corrupt database, corrupt object | `crash_recovery.rs`, `migrations.rs` |
| Unwritable output, abandoned staging, impossible disk reserve | `crash_recovery.rs`, `capture_recovery.rs`, `backup_restore.rs` |
| Lock contention and second writer | `writer_concurrency.rs` |
| Path traversal, duplicate inventory paths, unlisted files | `package_paths.rs`, `backup_restore.rs` |
| Cancellation and stale results | `desktop_jobs.rs`, `worker_*`, CLI tests |

The fuzz targets are bounded `proptest` properties on the stable toolchain, so
they run in the normal battery and every failure is replayed deterministically.
`docs/testing.md` explains why a separately pinned nightly/libFuzzer harness is
not part of the release gate.

## Out of scope / not claimed

- **No malware execution.** Parsers interpret bytes; they do not execute
  artifacts. A malicious document can still exploit a parser bug, which is why
  record adapters are isolated and limits are enforced.
- **No network.** The application does not upload evidence or fetch artifact
  URLs. Dependency advisory scanning in CI is build tooling, not application
  behavior.
- **No truth claim about the host.** A package proves what the case recorded,
  not that collection was complete or that the host was honest.
- **No legal custody claim.** Signatures and digests support custody; they do
  not by themselves satisfy a legal chain-of-custody requirement.
- **No free-text scrubbing.** Redaction is field-granular. A secret embedded
  inside an unselected field is not removed.
- **No cross-platform claim without a run.** Linux x86_64 is tested here.
  Windows and macOS safety modules require their own runs before being
  described as supported.
- **No certification.** No external forensic practitioner review has been
  recorded for this revision. The review scope is the fixtures, tests, and
  documented limits in this repository; that is not a certification.
