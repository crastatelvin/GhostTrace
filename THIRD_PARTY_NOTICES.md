# Third-party notices

GhostTrace is distributed as source. Its first-party code is licensed under
Apache-2.0 or MIT, at your option (see `LICENSE-APACHE`, `LICENSE-MIT`).

## Dependencies

All third-party Rust dependencies (crates published on crates.io) are
resolved by the committed `Cargo.lock`, which is the authoritative inventory
of their exact versions and sources. As of the P0.2 snapshot, the resolved
graph contains 436 packages, all under permissive licenses (MIT, Apache-2.0,
BSD-2/3-Clause, ISC, Zlib, Unicode-DFS, 0BSD, CC0-1.0). No GPL-only
dependency is used; two packages are dual-licensed with a copyleft
alternative that is **not** elected:

- `r-efi`: `MIT OR Apache-2.0 OR LGPL-2.1-or-later`
- `self_cell`: `Apache-2.0 OR GPL-2.0-only`

Release packaging generates the complete per-dependency notice list from the
lockfile (`xtask package`, P11); this file records policy and the policy
exceptions, and is not hand-maintained as a full inventory.

## Native dependencies

The desktop application links platform-provided libraries through the
windowing/rendering stack (an unavoidable characteristic of native GUI
toolkits): on Linux, X11/Wayland client libraries and an OpenGL or Vulkan
implementation; on Windows, OS-provided system libraries; on macOS,
system frameworks. These remain under their own licenses, are not modified,
and are not redistributed by this project.

## Bundled SQLite

`rusqlite` is used with the `bundled` feature, which compiles SQLite from the
maintained amalgamation shipped by rusqlite. SQLite is in the public domain
(https://sqlite.org/copyright.html). `docs/releases.md` records the exact
linked SQLite version (3.53.2 at the P0.1 snapshot) and its compile options.

## Fonts and assets

No fonts, icon sets, or branding assets from commercial forensic products are
used or copied. Any future assets carry their own license headers or a notice
in this file (plan Section 4).

## Fixtures and datasets

Tracked test fixtures are licensed as documented in
`tests/fixtures/LICENSE.md` and verified by `xtask fixtures --verify`. Large
public corpora are not redistributed: they are fetched only by explicit
maintainer validation jobs after per-corpus license review (plan Section 15).
