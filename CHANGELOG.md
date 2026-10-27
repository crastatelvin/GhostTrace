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
