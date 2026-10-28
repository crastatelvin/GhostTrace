# Quickstart

This guide builds GhostTrace from source and runs the documented checks. It
covers the P0 state: the storage/runtime stack is verified, but no forensic
feature exists yet — the first commands here prove the workspace, not an
investigation.

## Prerequisites

| Requirement | Notes |
|---|---|
| Rust 1.99.1 | Pinned by `rust-toolchain.toml`; `rustup` selects it automatically. Components `rustfmt` + `clippy` are declared there. |
| A C toolchain | `cc`/`gcc`; rusqlite compiles the bundled SQLite from source. |
| Cargo network access | Once, to fetch crates; builds are thereafter `--locked`/offline. |
| Linux desktop extras | libX11, libXcursor, libXrandr, libXi, EGL/GL runtime (Mesa works) for the glow renderer; a Vulkan loader for the optional `wgpu` feature. |

Windows and macOS builds are intended but not yet verified; see
`docs/releases.md` for the platform matrix and known gaps.

## Build

```bash
git clone https://github.com/crastatelvin/GhostTrace.git
cd GhostTrace
rustup show                      # installs the pinned toolchain
cargo build --workspace --locked
```

Binaries land in `target/debug/` (`ghosttrace-cli`, `ghosttrace-desktop`).

## Run the checks

```bash
cargo run -p xtask -- check
```

This runs, exactly as CI does: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`,
`cargo test --workspace --locked`, the desktop `wgpu` feature build, fixture
catalog verification, and the tracked-path policy checks. If any step is new
to you, read `docs/testing.md` for what each covers.

Verify the tracked fixture catalog alone with:

```bash
cargo run -p xtask -- fixtures --verify
```

## Inspect the verified storage stack

```bash
cargo run -p ghosttrace-cli -- sqlite-info
```

This prints the linked SQLite runtime report: rusqlite and SQLite library
versions, compile options (FTS5, thread-safety, foreign keys, WAL options),
and the results of the FTS5/foreign-key/defensive-schema/WAL checks. It is
the P0.1 evidence that the storage stack works as planned, recorded by
`docs/releases.md`.

## Run the desktop app

```bash
cargo run -p ghosttrace-desktop
```

The P6.2 shell creates or opens a case, captures a source directory, imports one
captured object, then browses the timeline with filters, a declared-bin
histogram, and a provenance inspector for each event. Progress, cancellation,
and recovery review are included. See [gui-guide.md](gui-guide.md). `--renderer wgpu` selects the optional backend.
With the `screenshot` cargo feature and the glow renderer,
`EFRAME_SCREENSHOT_TO=shot.png` writes one frame and exits.

## Working on tasks

```bash
cargo test -p ghosttrace-core --test <name> --locked   # focused test
git add <explicit paths> && git diff --cached           # never `git add .`
```

Phased work, commit messages, and gates are defined in
`docs/plans/2026-10-23-ghosttrace-master-plan.md` (Sections 16–18).
