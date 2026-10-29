# Platform support and build prerequisites (P0.1 baseline)

This file records what P0.1 (2026-10-23) actually verified on the toolchain
pinned in `rust-toolchain.toml` (1.99.1, edition 2024). It is a build-inputs and
platform matrix document, not a release announcement.

## Verified environment

- OS: Arch Linux (rolling), x86_64.
- Display: Xwayland X11 (`DISPLAY=:0`, 1366x768, 59.62 Hz) and the host's native
  Wayland session both exercised; the GUI pilot ran on each.
- Toolchain: Rust 1.99.1 + rustfmt + clippy (rust-toolchain.toml).
- Native build deps present: gcc, libX11/libxcursor/libxrandr/libxi, Mesa GL,
  Vulkan loader with radeon/nouveau/intel/lvp ICDs.

## Platform matrix (planned first-tier support)

| Target | CLI/TUI | Desktop | Verification status |
|---|---|---|---|
| Linux x86_64 | planned | planned | **Build + run verified on this host** (glow default) |
| Windows x86_64 | planned | planned | Not verified; re-run renderer choice there |
| macOS arm64 | planned | planned | Not verified; re-run renderer choice there |
| Linux arm64 / macOS x86_64 | planned | planned | Not verified |

"Build + run verified" means the P0.1 pilot built and ran with observable frame
pacing and a background job; it is not a claim about forensic capability or
release packaging.

## Build prerequisites (source)

1. Install Rust 1.99.1 via rustup; this repository pins the toolchain, so
   `rustup` will select it automatically.
2. Linux desktop (glow): system libs for X11/Wayland windows and OpenGL
   (libX11, libXcursor, libXrandr, libXi, EGL/GL runtime — e.g. Mesa). No
   network access is required after `cargo fetch`.
3. Linux desktop (wgpu feature): a working Vulkan loader + ICD.
4. Build offline: `cargo build --workspace --locked` after `cargo fetch`
   (lockfile is committed); `cargo vendor` output is generated at release time.

## Verified runtime facts (SQLite storage stack)

- rusqlite 0.40.2 `bundled` links SQLite **3.53.2** (confirmed via
  `SELECT sqlite_version()`), not merely the crate version. This matches the
  value researched in the plan's Section 3.
- Compile options include `ENABLE_FTS5`, `THREADSAFE=1`, `DEFAULT_FOREIGN_KEYS`,
  `ENABLE_API_ARMOR`, `DEFAULT_WAL_SYNCHRONOUS=2`, `ENABLE_DBSTAT_VTAB`,
  `USE_URI`. Verified at runtime: FTS5 virtual table creation + phrase match,
  foreign-key enforcement, `PRAGMA trusted_schema=OFF`, and `journal_mode=WAL`
  with a read-back write. (`ghosttrace-cli sqlite-info` prints this report.)
- Caveat recorded for P4 (browser adapters): the bundled build has
  `ENABLE_LOAD_EXTENSION` at the C level. rusqlite's `loadable_extension`
  feature is deliberately not enabled, so the Rust API does not expose it;
  parser inputs must additionally be opened defensively (read-only private
  copies, `trusted_schema=OFF`), as the plan requires.

## Dependency and license inventory

- 436 transitive packages resolve under the committed `Cargo.lock`; licenses are
  permissive (MIT / Apache-2.0 / BSD / ISC / Zlib / Unicode-DFS). Two entries are
  dual-licensed with a copyleft alternative we do not elect:
  `r-efi` (MIT OR Apache-2.0 OR LGPL-2.1-or-later) and `self_cell`
  (Apache-2.0 OR GPL-2.0-only); no package is GPL-only.
- `Cargo.lock` is the authoritative full inventory for this snapshot.
  `THIRD_PARTY_NOTICES.md` is generated from the lockfile as part of P0.2/P11
  packaging, not hand-maintained.
- Direct dependencies (P0.1): serde, serde_json, sha2, rusqlite (bundled),
  tokio, clap, tracing, eframe/egui (glow default). No dependency outside the
  plan's Section 3 table has been added.

## Known gaps recorded at P0.1

- Accessibility smoke tests: AccessKit and the AT-SPI Unix adapter are compiled
  in and wired, but a live screen-reader run could not be executed on this host
  (installed Orca fails to initialize against the host's rootless Xwayland X
  server with an XKB error; the AT-SPI status service is absent from this
  session). NVDA (Windows) and VoiceOver (macOS) require those machines.
  Screen-reader verification therefore remains a release-target gate, per the
  plan's P6/P10 schedule. This is a host-environment limitation, not a
  discovered framework incompatibility.
- Only Linux x86_64 has build+run evidence. Windows/macOS support statements
  wait for actual verification; nothing in the repository should imply they are
  supported yet.

## P6.4 desktop bundle and appearance (2026-10-28)

- `cargo run -p xtask -- package --version <v>` now requires the CLI and the
  desktop binary and ships `bin/ghosttrace` + `bin/ghosttrace-desktop` together
  with licences, the CLI/GUI/report/release docs, the sample folder, `help.txt`
  (CLI `--help`), and a `build-info.json` inventory of every packaged file with
  its SHA-256. The desktop binary supports `--version` without a display server,
  so the extracted bundle can be smoke-run headlessly; packaging refuses a
  desktop binary that fails that check.
- The archive is `ghosttrace-<version>-<target>.tar.gz` plus a matching
  `.sha256`; packaging still refuses to overwrite an existing archive.
- Appearance: Dark (default), Light, and High contrast, selected in the header.
  The choice is per session. High contrast is a black background with white
  text, opaque selection, and thicker strokes; no meaning relies on hue.
- Accessibility status at P6.4: every screen's controls are named and reachable
  by keyboard in the `egui_kittest`/AccessKit tree, custom views (the
  relationship graph) have a keyboard-reachable list equivalent, and the
  timeline/graph/findings selection keys are covered by tests. A **live
  screen-reader run was not possible on this host**: Orca fails against the
  rootless Xwayland server (`XkbSetMap BadValue`) and NVDA/VoiceOver need their
  own machines. This remains a P10 release-target gate; it is not an
  accessibility certification.
- Renderer status: glow is the default and has been run on this host. The wgpu
  feature compiles in `xtask check`; rendering through wgpu was not exercised in
  this session, so it is built but not claimed as verified.
- Desktop report export is unredacted until P9.2. The report screen states this
  before the export control.

## P7 interactive terminal (2026-10-28)

- `ghosttrace tui` was smoke-run on Linux x86_64 under a real pty
  (`script -qec ... /dev/null`, input `q`): exit code 0, the alternate screen
  was entered and left exactly once, and the cursor was hidden and shown
  exactly once. A missing case exits 1 before the alternate screen is entered.
- Terminal cleanup is unit-tested for a normal restore, an enter failure
  (nothing to restore), and an unwinding panic. A quit through `q`/`Ctrl+C`
  takes the same early-return path as a normal exit.
- Redirected stdin/stdout is refused with exit code 2 and no ANSI bytes; the
  plain CLI JSON output is asserted to contain no ESC bytes.
- **Not verified on this host:** Windows Terminal and macOS terminals (no such
  machines here). They remain P10 release-target smoke checks, not passes.
- `0.3.0-beta.1` promotion still waits on the open accessibility and
  release-target gate items recorded above; no tag was created by P7.

## P8.1 structured EVTX ingestion (2026-10-28)

- Three real Windows logs from the public `evtx` parser sample set are tracked
  with provenance and SHA-256 (`tests/fixtures/evtx/README.md`): Security 4625
  (failed logon), Security 4624 (successful logons), and Sysmon 1 (process
  creation). The `evtx` 0.13.0 crate is built without its default
  `multithreading`/`evtx_dump` features.
- Import tests read them through capture and assert the mapped kinds and
  fields, payload `EventRecordID` locators (unique per object), UTC logging
  time, the Sysmon payload occurrence time with its recorded UTC assumption,
  and that unmapped providers stay generic observations.
- The Sysmon fixture contains 8 unreadable chunks: the run ends `partial` with
  `evtx_parse_error` diagnostics. A truncated chunk area (5000-byte and
  70000-byte prefixes) ends `partial` with `truncated_evidence` even though the
  parser returns the chunks it can read; a 100-byte prefix fails with exit 2
  and records no run. The header's own chunk counter is stale on these dirty
  logs, so truncation is judged from the 64 KiB chunk alignment.
- No provider message DLL is loaded, no DTD/entity is resolved, and nothing
  named by a record is executed or fetched. A hostile payload string is asserted
  to survive verbatim in the raw observation.
- Remaining P8 work (P8.2 parser worker isolation) is not started.

## P8.2 isolated parser workers (2026-10-29)

- EVTX and journal-export decoding runs in `ghosttrace worker --protocol 1`, a
  private mode of the packaged CLI resolved beside the desktop binary (or
  explicitly), never through `PATH`. A missing or mismatched build is refused
  and recorded as a failed run.
- Records cross a length-prefixed JSON protocol: 64 KiB control frames, 32 MiB
  batch frames, 500 records per batch, strict job/sequence/count checks, and
  per-record bounds on locators, JSON bodies, kinds, times, and diagnostics.
  Raw `i128` times travel as exact decimal text because `serde_json` cannot
  deserialize them.
- The worker gets a cleared environment, a private `0700` copy of the object
  (never a case path), and a null stderr. On Linux it also gets a new session,
  `no_new_privs`, and `RLIMIT_AS`/`CPU`/`FSIZE`/`NOFILE`/`CORE` limits; the
  parent kills it after 30 s without output or 30 min total, and on cancel.
- Tests: `worker_protocol.rs` (framing, validation, handshake/path refusals),
  `worker_crash.rs` (hang, crash, garbage, oversize frame, foreign job, build
  mismatch, cancellation), and `worker_limits.rs` (worker vs in-process output
  equality on the tracked EVTX fixture, record and record-size limits).
- **Not claimed:** no network namespace/seccomp, no filesystem namespace, no
  rlimits on macOS/Windows, and the browser adapter still runs in-process.
  These are recorded in `docs/worker-protocol.md` instead of being implied.
- `0.3.0-beta.1` promotion still waits on the open accessibility and
  release-target gate items; no tag was created by P8.2.
