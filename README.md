# GhostTrace

**A local-first Rust forensic workbench that reconstructs searchable timelines
from captured artifacts, shows the evidence and uncertainty behind each claim,
compares file snapshots, and produces verifiable investigation packages.**

GhostTrace is a forensic *analysis* tool for artifacts you are authorized to
examine — not an endpoint monitoring agent. It works offline, never uploads
evidence, never fetches URLs found in artifacts, and records what is unknown
instead of silently converting gaps into results.

## Status

**Early development.** P0 (stack feasibility) is complete; the first forensic
capability (evidence model and case storage, P1) has not started. Nothing in
this repository is yet able to analyze real evidence. See
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
