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
- P4.2 (2026-10-27): binary-safe systemd journal export ingestion — ordered
  `[name, value]` raw pairs keep repeated fields, binary values are preserved
  as hex, and `__CURSOR` is stored verbatim. Length-prefixed fields, truncated
  lengths, oversized entries, and framing errors produce structured
  diagnostics instead of partial records. Realtime timestamps position events;
  monotonic timestamps are stored with clock domain `boot:<_BOOT_ID>` and are
  never ordered across boots (`compare_boot_times`). Native `.journal` files
  remain out of scope: capture `journalctl -o export` externally.
- P4.3 (2026-10-27): captured Chromium and Firefox history packages — SQLite
  contract validation with recorded schema fingerprints, digest-verified
  private copies, committed-WAL application, and explicit `wal_missing`,
  inconsistent-sidecar, and unavailable-download-field diagnostics. Chromium
  visits/downloads and Firefox visits become `browser.visit`/`browser.download`
  events with exact 1601/Unix-epoch times, referrers, transitions, sync/source
  labels, and preserved download URL chains. Views, virtual tables, SQL limits,
  a query deadline, corrupt pages, and missing contract columns are rejected
  instead of parsed best-effort (`docs/formats.md`).
- P4.4 (2026-10-27): indexed search and reviewed timestamp normalization —
  `ghosttrace search` over an FTS5 external-content index of summary/kind/host
  text with a validated grammar bound as a parameter (no operator text in SQL),
  the same structured filters and keyset paging as `timeline`, a rebuildable
  index that cannot alter a recorded event, and a migration that indexes
  existing cases. Each import now records its own revision, so re-importing
  with different `--year`/`--timezone` assumptions keeps both interpretations
  with their recorded assumptions (`parse_runs.assumptions_json`), and reports
  pin one revision (`--revision`) so a published report stays reproducible.
  `timeline`/`report` gained revision selection; defaults read the newest
  revision of the latest acquisition (`docs/cli.md`, `docs/storage.md`).
- P5.1 (2026-10-28): scoped entity resolution and explainable relationships —
  host/user/IP/process/path/digest entities scoped by host, boot, and
  acquisition (a PID never joins across hosts or boots); documented adapter
  fields only, never message text; `correlate.digest_equal` (observed: equal
  bytes, not a proven copy) and `correlate.shared_ip` /
  `correlate.shared_basename` (candidates only); bounded buckets, pair budget,
  edge budget, and temporal windows with skipped/truncated/untimed counts;
  keyset `query_relationships`; migration 0004 links events to their source
  record (`docs/architecture.md`, `docs/storage.md`, `docs/formats.md`).
- P5.2 (2026-10-28): explainable findings and analyst review history — five
  compiled rules with fixed ids/versions and validated TOML parameters
  (unknown keys and out-of-range values rejected), each finding storing its
  supporting event ids, exact predicates, severity, rationale, and remaining
  alternatives, with per-rule counts and `not_evaluated` reasons recorded on
  the analysis run. Deterministic run and finding ids make replays idempotent
  and preserve analyst state; notes, tags, and dispositions are append-only
  revisions where a stale edit is a `conflict` instead of an overwrite, and a
  dismissal survives re-analysis. Named saved views store typed, validated
  filters (no SQL) that run through the shared query path. `ghosttrace analyze`
  prints the report. No rule output expresses a probability of maliciousness
  (`docs/architecture.md`, `docs/storage.md`, `docs/formats.md`, `docs/cli.md`).
- P6.1 (2026-10-28): native desktop case and evidence workflow — case
  create/open with display zone, capture (protected copy or live best effort)
  with limits and a pre-start summary, captured-object import with explicit
  format and optional RFC 3164 zone/year, single-job progress and immediate
  cancellation, and a recovery review for jobs interrupted at the previous
  close (acknowledged, never auto-completed). State and command/result
  messages keep SQLite and evidence access out of render callbacks, and stale
  job results are discarded by id. The P0.1 pilot app is replaced by this shell.
  Headless `egui_kittest` tests address controls by accessible name
  (`docs/gui-guide.md`).
- P6.2 (2026-10-28): responsive native timeline and provenance inspector —
  validated search plus exact kind/host/source filters, a 350 ms debounced
  query with generation-based supersession, a declared-bin histogram that
  filters to a selected window, a virtualized keyset-paged list with a bounded
  1,000-row cache, an explicit unresolved view, and a resizable inspector that
  shows the raw record and locator, recorded times and assumptions, scoped
  entities, parser identity, and run diagnostics with copy actions and an
  inert escaped preview. Reads run on a second worker thread with their own
  reader, so an import never blocks the UI. A 1,000,000-event measurement
  (page 1 ms, histogram 0.5 s, detail 1 ms, phrase search 1.4 ms) exposed an
  FTS join plan that scanned every event (33 s); the FTS subquery now drives
  the join and a query-plan test guards it. New core contracts:
  `event_detail()`, `event_histogram()`, and display escaping
  (`docs/gui-guide.md`).
- P10.1 (2026-10-29): bounded fuzz targets on the time, native-path, manifest,
  CSV/display, and worker-frame boundaries; a strict native-path decoder
  regression (non-ASCII encoded text is rejected, not truncated); crash
  recovery tests for unwritable output, abandoned staging, impossible disk
  reserve, truncated databases, and corrupted objects; `xtask deps` license
  allowlist plus optional `cargo-audit`; scheduled security workflow; a
  threat-model document; and removal of unused `tokio`/`tracing` dependencies.
- P9.2 (2026-10-29): redacted exports, spreadsheet-safe CSV, portable packages,
  and verified backup/restore — `report --redact`/`--csv` publishes a projection
  with a value-free `redaction.json` ledger (field names and counts only) while
  the case and stored bytes stay untouched. CSV escapes control characters and
  neutralizes `=`/`+`/`-`/`@` formula prefixes; JSON stays exact. `package`
  builds a self-describing directory (manifest, cited objects, report JSON/HTML/
  CSV, verifier README, SHA-256 inventory) that `verify-package` checks
  independently, rejecting missing, modified, unlisted, duplicate, or escaping
  paths; the inventory can be signed with the P9.1 envelope. `backup` takes a
  consistent online SQLite snapshot plus every referenced object, config, and
  manifest with an inventory, and `restore` re-verifies digests, integrity,
  schema, and every object reference in a private staging directory before
  publishing a new case. The desktop report screen exposes the redaction
  selection, CSV export, and backup/restore jobs. The P9 gate passes: an
  untampered package is accepted, a modified byte is rejected, and a relocated
  case reopens and verifies.
- P9.1 (2026-10-29): signed evidence manifests with explicit key trust —
  detached Ed25519 signatures over the exact manifest bytes
  (`b"GhostTrace manifest v1"` + NUL + SHA-256 of the complete file) in a
  versioned `<manifest>.sig.json` sidecar. Keys are standard encrypted PKCS#8
  (PBES2 + scrypt + AES-256-CBC) created with mode `0600`, OS randomness, and
  zeroization; loading refuses symlinks, group/other-readable files, foreign
  ownership, oversized files, legacy PBES1, non-AES-256-CBC ciphers, and
  out-of-bound KDF parameters. `ghosttrace key generate|import|public`,
  `ghosttrace sign`, and `verify --signature/--trust` prompt for passphrases on
  a terminal only. Verification reports object digests, signature validity, and
  key trust as separate statuses, so a valid signature from an unknown key is
  "valid signature, untrusted key", never a silent success or a false failure.
  The desktop verify screen shows the same statuses plus capture completeness
  and can sign a manifest with a password field that is cleared after use.
  Known-answer tests pin the domain message against an independent OpenSSL
  signature, and the RFC 8032 vector is checked.
- P8.2 (2026-10-29): isolated parser workers — EVTX and journal-export
  decoding runs in a private-mode subprocess (`ghosttrace worker --protocol 1`)
  resolved beside the application, never through `PATH`. The worker gets a
  `0700` copy of the object (never a case path), a cleared environment, and, on
  Linux, a new session, `no_new_privs`, and `RLIMIT_AS`/`CPU`/`FSIZE`/`NOFILE`/
  `CORE` bounds. Records cross a length-prefixed JSON protocol with control and
  batch frame bounds, a 500-record batch cap, monotonic sequence numbers, exact
  count reconciliation, and per-field validation; a crash, hang, bad frame, or
  lying worker records the run `failed` (with `worker_timeout`,
  `worker_crashed`, `worker_protocol`, `worker_error`, or `worker_start_failed`)
  and can never produce `completed`. A 30-second no-progress deadline and a
  30-minute job budget bound every job; cancellation kills the worker. The
  worker path is tested against the in-process baseline on the tracked EVTX
  fixture, including `--max-records` and `--max-record-bytes`. The browser
  adapter remains in-process and the missing network/filesystem sandbox is
  documented rather than assumed (`docs/worker-protocol.md`).
- P8.1 (2026-10-28): structured EVTX ingestion — captured Windows event logs
  are detected by their `ElfFile\0` signature or declared with
  `--format evtx`; structured `System`/`EventData` fields are preserved and each
  record carries its payload `EventRecordID` as the locator. Tested mappings
  cover Security 4624/4625 and Sysmon 1/Security 4688; every other provider
  stays a structured `windows.event_log` observation. The logging time is the
  UTC `System/TimeCreated`; Sysmon 1 adds a separate `occurred` time from
  `UtcTime` with the UTC assumption recorded. Unreadable chunks and a truncated
  chunk area end the run `partial` instead of silently succeeding, a header-less
  file is refused, provider message resources are never loaded, and payload
  text (including DTD/entity-looking strings) is preserved verbatim. Three real
  sample logs are tracked with provenance in `tests/fixtures/evtx/`.
- P7 (2026-10-28): interactive terminal workflow — `ghosttrace tui` with a
  paginated timeline, shared-grammar search, exact kind/host/source/time
  filters, event detail, five-rule findings, a status/progress line, and an
  always-visible key footer; evidence text is escaped before rendering and
  table cells flatten newlines; a restoration guard covers normal exit, early
  quit, error, and unwind; redirected output is refused so pipelines stay plain.
  The CLI is now a library plus a thin binary so TUI state/input transitions are
  tested without a terminal. Linux pty smoke verified enter/leave and cursor
  restoration exactly once; Windows Terminal and macOS terminal checks remain
  recorded P10 gate items.
- P6.4 (2026-10-28): desktop reporting and accessible investigation workflow —
  unredacted report export through the shared `reports::build_report`/`publish`
  path with an explicit scope/time-zone/revision summary, absolute-and-outside-
  case destination validation, job cancellation that publishes nothing, visible
  failed publications, and manifest verification results; dark/light/high-
  contrast palettes with explicit empty/loading/error states; `xtask package`
  now ships and smoke-checks the CLI/desktop pair plus licences and
  `THIRD_PARTY_NOTICES.md`; report provenance records the front end that built
  it (`generated_by`). Fixed the desktop acquisition list query (it ordered by a
  nonexistent column, so reopening a case with captures failed). Live
  screen-reader runs remain a recorded P10 gate limitation.
- P6.3 (2026-10-28): snapshot comparison and explainable analysis in the
  desktop — coverage-aware diff of two recorded captures with scope verdict,
  warnings, per-class counts, keyset paging, and `unknown` kept as its own
  visible class; relationship list with a bounded graph (40 nodes / 80 edges)
  whose edges reveal supporting events and open them in the timeline inspector;
  findings with severity bands, rationale, alternatives, recorded predicates,
  and append-only disposition history; event notes, tags, and bookmarks as
  annotations; and typed saved views that restore the timeline filters. All
  reads run on the query thread, all writes (analysis, correlation,
  annotations, views) on the single job worker, and every command carries a
  generation or job id so stale results change nothing. New core entry point:
  `CaseSession::compare_acquisitions()` (`docs/gui-guide.md`).
