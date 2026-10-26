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
