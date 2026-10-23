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
