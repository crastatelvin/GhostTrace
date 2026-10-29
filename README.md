# GhostTrace

**A local-first Rust forensic workbench that reconstructs searchable timelines
from captured artifacts, shows the evidence and uncertainty behind each claim,
compares file snapshots, and produces verifiable investigation packages.**

GhostTrace is a forensic *analysis* tool for artifacts you are authorized to
examine — not an endpoint monitoring agent. It works offline, never uploads
evidence, never fetches URLs found in artifacts, and records what is unknown
instead of silently converting gaps into results.

## Status

**Pre-1.0, Linux x86_64 verified.** P0–P10 are complete: safe capture, JSONL /
syslog / journal-export / browser-history / EVTX import, the indexed timeline,
search, coverage-aware diff, scoped entities and bounded relationships, five
explainable rules with notes and saved views, the native desktop workbench, the
terminal UI, Ed25519 signing, redacted reports and verifiable packages,
backup/restore, fuzzing and crash recovery, and measured performance baselines.
P11 (verified release distributions) is next. Windows and macOS are intended
targets but unverified; see `docs/releases.md` for the platform matrix and
known gaps. The phased plan and tracker are in
`docs/plans/2026-10-23-ghosttrace-master-plan.md`.

| Release | Deliverable |
|---|---|
| 0.1.0-alpha.1 | Reliable folder timeline |
| 0.2.0-alpha.1 | Multi-source investigation (logs, journal, browsers, FTS) |
| 0.3.0-beta.1 | Native desktop workbench + TUI |
| 0.4.0-beta.1 | Hardened forensic package (EVTX, isolation, signatures) |
| 1.0.0 | Supported open-source release |

These identifiers describe gates, not deadlines.

## Workflow (CLI)

```bash
cargo build --workspace --locked --release
export PATH="$PWD/target/release:$PATH"

ghosttrace case create --case /cases/demo.ghosttrace-case --label demo
ghosttrace scan --case /cases/demo.ghosttrace-case --source /evidence/export
ghosttrace import --case /cases/demo.ghosttrace-case --path logs/app.jsonl \
  --format jsonl --time-field ts --kind-field kind --host-field host --message-field msg
ghosttrace timeline --case /cases/demo.ghosttrace-case --last 24h
ghosttrace analyze --case /cases/demo.ghosttrace-case
ghosttrace report --case /cases/demo.ghosttrace-case --output /cases/reports --csv
```

`scan` copies and hashes every file it can access, records each omission with a
stable code, and writes an acquisition manifest. Exit `0` means no material
omission, `3` means the result is partial or was cancelled, `1` means the
operation failed, `2` means invalid usage, `4` means verification failed.
Prefer capturing from a protected copy; `--method live-best-effort` is
explicitly best effort and the warning is printed where the choice is made.
Reading files may affect access-time metadata; that effect is disclosed, not
asserted absent.

Run the ten-minute [folder walkthrough](docs/walkthrough.md), or the two tracked
synthetic investigations in [`samples/`](samples/README.md) (failed logons →
success → process/file activity; two snapshots with misleading metadata and a
coverage gap).

## Documentation

| Guide | Contents |
|---|---|
| [Installation](docs/installation.md) | build, release archive, first case, upgrades, licensing, custody |
| [Quickstart](docs/quickstart.md) | prerequisites, checks, desktop build |
| [CLI](docs/cli.md) | every command, output contract, exit codes, TUI keys |
| [Desktop](docs/gui-guide.md) | screens, keyboard, accessibility, measured responsiveness |
| [Verification and reports](docs/reports.md) | manifests, signatures, redaction, HTML/CSV |
| [Samples](samples/README.md) | two tracked synthetic investigations |
| [Limitations](docs/limitations.md) | unsupported formats, custody, platform, performance |
| [Troubleshooting](docs/troubleshooting.md) | permissions, WAL, schema, time, signatures, backup |
| [Formats](docs/formats.md) | mappings, bounds, rule parameters, signing formats |
| [Timestamps](docs/timestamps.md) | statuses, zones, precision versus accuracy |
| [Storage](docs/storage.md) | schema, revisions, jobs, recovery |
| [Performance](docs/performance.md) | measured baselines and the narrowed ingest target |
| [Testing](docs/testing.md) | fuzz, recovery, dependency, and platform matrix |
| [Threat model](docs/threat-model.md) | trust boundaries and claims not made |
| [Releases](docs/releases.md) | verified environment and known gaps |

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
