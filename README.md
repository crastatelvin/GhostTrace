# GhostTrace

**A local-first Rust forensic workbench that reconstructs searchable timelines
from captured artifacts, shows the evidence and uncertainty behind each claim,
compares file snapshots, and produces verifiable investigation packages.**

GhostTrace is a forensic *analysis* tool for artifacts you are authorized to
examine — not an endpoint monitoring agent. It works offline, never uploads
evidence, never fetches URLs found in artifacts, and records what is unknown
instead of silently converting gaps into results.

## Status

**Early development.** P0 (stack feasibility), P1 (evidence model, lossless
paths and timestamps, transactional case storage, shared query service), and
P2 (safe capture, streaming copy/hash, recovery, and the `case`/`scan`/`status`
CLI) are complete. The tool can capture a folder into a verifiable case today;
timeline parsing and analysis arrive with P3+. See
`docs/plans/2026-10-23-ghosttrace-master-plan.md` for the full phased plan and
current tracker, and `docs/releases.md` for the verified platform baseline.

| Release | Deliverable |
|---|---|
| 0.1.0-alpha.1 | Reliable folder timeline |
| 0.2.0-alpha.1 | Multi-source investigation (logs, journal, browsers, FTS) |
| 0.3.0-beta.1 | Native desktop workbench + TUI |
| 0.4.0-beta.1 | Hardened forensic package (EVTX, isolation, signatures) |
| 1.0.0 | Supported open-source release |

These identifiers describe gates, not deadlines.

## Alpha workflow (CLI)

```bash
cargo build --workspace --locked
./target/debug/ghosttrace case create --case /cases/demo.ghosttrace-case --label demo
./target/debug/ghosttrace scan --case /cases/demo.ghosttrace-case --source /evidence/export
./target/debug/ghosttrace status --case /cases/demo.ghosttrace-case
./target/debug/ghosttrace timeline --case /cases/demo.ghosttrace-case --last 24h
./target/debug/ghosttrace diff --case /cases/demo.ghosttrace-case --before <ACQ> --after <ACQ>
```

`scan` copies and hashes every file it can access, records each omission with a
stable code, and writes an acquisition manifest. Exit `0` means no material
omission, `3` means the result is partial or was cancelled, `1` means the
operation failed, `2` means invalid usage. Prefer capturing from a protected
copy; `--method live-best-effort` is explicitly best effort and the warning is
printed where the choice is made. Reading files may affect access-time
metadata; that effect is disclosed, not asserted absent. Full details:
`docs/cli.md`.

## License

Dual-licensed under Apache-2.0 (`LICENSE-APACHE`) or MIT (`LICENSE-MIT`), at
your option. Font, fixture, and bundled third-party material carry their own
notices (`tests/fixtures/LICENSE.md`, `THIRD_PARTY_NOTICES.md`).

## Building from source

```bash
rustup show            # installs the pinned 1.99.1 toolchain from rust-toolchain.toml
cargo build --workspace --locked
cargo run -p xtask -- check   # documented local checks
```

See `docs/quickstart.md` for prerequisites per platform. Windows and macOS are
planned targets but not yet verified; Linux x86_64 is the only platform with
build-and-run evidence today (`docs/releases.md`).

## Design principles

- **Evidence is immutable and hashed.** Source evidence is opened read-only;
  analysis operates on captured copies; every captured object is SHA-256
  verified.
- **Uncertainty is explicit.** Unknown timestamps, missing hashes, incomplete
  traversal, and parser failures are reported, never averaged away.
- **Facts and interpretations are separated.** Raw observations, normalized
  events, analyst annotations, and rule findings are separately versioned.
- **Integrity is exact-byte.** Manifests are signed over their exact stored
  bytes; verifiers separate byte integrity, signature validity, and key trust.
- **Offline by default.** No telemetry, no automatic updates, no network
  listeners unless explicitly enabled.

## Contributing

See `CONTRIBUTING.md`. Please report security issues privately per
`SECURITY.md` — and never upload real evidence anywhere.
