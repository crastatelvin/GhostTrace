# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
semantic versioning; the release ladder with its gates is defined in the plan
(`docs/plans/2026-10-23-ghosttrace-master-plan.md`, Section 2).

Version identifiers describe gates, not deadlines. During the phases, this
file records implemented capability only.

## [Unreleased]

### Added

- P0.1 (2026-10-23): verified Rust workspace and native desktop stack —
  workspace crates (`ghosttrace-core`, `ghosttrace-cli`,
  `ghosttrace-desktop`), pinned toolchain 1.99.1 with committed lockfile,
  rusqlite-bundled SQLite runtime verification (`ghosttrace-cli sqlite-info`
  reports SQLite 3.53.2, FTS5, foreign keys, defensive-schema and WAL checks),
  egui/eframe desktop pilot with measured frame pacing on glow and wgpu, and
  the glow default renderer decision (`docs/adr/0001-native-rust-ui.md`,
  `docs/releases.md`).
- P0.2 (2026-10-24): reproducible contributor checks (`xtask check`,
  `xtask fixtures --verify`), license/community/support files, CI with pinned
  actions, issue/PR templates, and quickstart/testing docs.
- P1.1 (2026-10-24): lossless native paths and exact timestamp semantics —
  `NativePath` (byte/code-unit identity, reversible interchange encoding,
  escaped display), `EventTime` with Resolved/Ambiguous/Unresolved/Invalid
  statuses and preserved raw values, Chromium/FILETIME/Firefox/epoch
  conversions, DST overlap and nonexistent-time handling, domain records
  (case, acquisition, evidence, observations, events), and error categories
  with stable machine codes (`docs/timestamps.md`, `docs/evidence-model.md`).
- P1.2 (2026-10-25): transactional case storage and the shared query service —
  private case directories with exclusive creation, the dedicated writer with
  bounded batches and all-or-nothing commits, checksummed sequential
  migrations with backup-before-migrate and newer-schema rejection, WAL-aware
  validated backups, read-only connections, keyset-ordered `EventQuery` /
  `EventPage` with an explicit unresolved view, job checkpoints with
  previously-running-job recovery detection, and startup SQLite diagnostics
  (`docs/storage.md`).
- P2.1 (2026-10-27): capture scope and the coverage ledger — validated
  `CaptureSpec` (case-store overlap, duplicate roots, symlink-follow and
  no-root rejection with stable codes), Unix no-follow traversal preserving
  byte-exact native relative paths, unix device/inode identity with hardlink
  aliasing, directory-loop identity guard, depth/entry/size caps disclosed in
  the ledger, FIFO/socket/device exclusion, permission-denied and vanished
  categories, bounded diagnostics, the ordinary-user permission test that
  self-skips under root, and the tracked `path-edges` fixture definition
  (`docs/architecture.md` capture section).
- P2.2 (2026-10-27): streaming copy, hashing, and recovery — one fixed
  64 KiB buffer hashes exactly the bytes written, private staging files sync
  and are atomically renamed into `objects/sha256/ab/<digest>` after an
  identity/size/mtime recheck (no-follow open, FIFO-safe), free-space reserve,
  bounded copy workers with explicit cancellation outcomes, and recovery
  inspection that reports abandoned staging and published-but-uncommitted
  objects without deleting evidence. Acquisition manifest v1 records method,
  tool version, roots, coverage counts, and per-object length/SHA-256 and
  verifies the stored copy. Capture metadata events (`file.observed`, application
  clock) and the `small-case` fixture definition complete the phase.
- P2.3 (2026-10-27): CLI alpha workflow — `case create`, `scan`, `status`, and
  `sqlite-info` with JSON on stdout, progress/warnings on stderr, documented
  exit codes (`0`/`1`/`2`/`3`), `Ctrl-C` cancellation that stops after the
  current chunk and keeps unstarted paths as explicit `unobserved` coverage,
  terminal-safe encoded native paths, protected-copy vs live-best-effort
  disclosure at the point of choice, and access-time effects stated
  (`docs/cli.md`, README alpha workflow).
- P3.1 (2026-10-27): timeline and snapshot diff — `ghosttrace timeline` with
  case-latest `--last` anchoring, explicit `--until`, a separate unresolved
  view, exact kind/host/source filters, and keyset pages; `ghosttrace diff`
  comparing recorded hash/size/mtime with scope-first validation,
  coverage-gap awareness, and `move_candidate` rather than rename claims.
  Migration `0002_file_times` adds nullable source mtime columns so metadata
  comparisons rest on captured facts. Documented class semantics and limits
  (`docs/cli.md`, `diff --help`).
- P3.2 (2026-10-27): verification and safe reports — `ghosttrace verify`
  re-hashes stored objects and fails with exit 4 on tampering, missing objects,
  duplicate JSON keys, unsupported versions, duplicate references, or unsafe
  store paths; `ghosttrace report` publishes a versioned `ghosttrace-report/1`
  JSON plus a self-contained escaped HTML view (no scripts, links, or remote
  resources; control/bidi characters rendered visibly), atomically and without
  overwriting an earlier export. Added `xtask package` archive/checksum output
  with a build/target inventory, a ten-minute walkthrough with exact expected
  results (`docs/walkthrough.md`), report docs, and prerelease notes.
- P4.1 (2026-10-27): bounded log ingestion — `ghosttrace import` with
  signature detection or a recorded manual override, deterministic versioned
  parse runs, exact byte locators, idempotent replays, and structured
  diagnostics for oversized, non-UTF-8, malformed, or schema-mismatched
  records. JSONL uses a fixed field/time-format mapping with no executable
  expressions. RFC 5424 and selected RFC 3164 headers preserve raw fields;
  RFC 3164 times stay unresolved without an operator-supplied year/zone, DST
  overlaps stay ambiguous, and December→January sequences are never silently
  rolled. Only tested sshd/sudo outcomes become events; everything else stays
  raw (`docs/formats.md`).
