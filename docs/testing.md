# Testing

GhostTrace's test philosophy is forensic: the tests must be able to catch
**wrong behavior**, not restate implementation. Snapshot-style assertions are
reserved for selected normalized fields and provenance, never for unstable
UUIDs or wall-clock timestamps (plan Section 15).

## Layers

| Layer | What it proves | Where |
|---|---|---|
| Unit/property tests | Domain semantics: timestamp conversions, native paths, query ordering, rule logic | `crates/*/tests`, e.g. `time_semantics.rs` |
| SQLite integration | Transactional batches, migrations, idempotency, writer concurrency, recovery | `tests/case_storage.rs`, `migrations.rs`, `writer_concurrency.rs` |
| CLI/subprocess contracts | Exit codes, JSON-safe output, progress on stderr, Ctrl-C handling | `tests/cli_*.rs` |
| GUI accessible-tree tests | Controls reachable by accessible role/name; result supersession | `egui_kittest` (P6) |
| Adversarial/fuzz | Oversize, truncation, hostile payloads, recovery from injected failures | `tests/hostile-inputs` fixtures, fuzz targets (P10) |
| Platform traversal | no-follow containment, permissions, name encodings on each OS | platform test modules, run as an ordinary user |
| Benchmarks | p95 query, ingest throughput, peak RSS on generated corpora | `cargo criterion` benches, `xtask` scale harness (P10) |

## Fixtures

Tracked fixtures are small, licensed, and cataloged in
`tests/fixtures/catalog.toml`; large corpora (NIST CFReDS, Digital Corpora)
are fetched only by explicit maintainer validation jobs after license review.
Verify the catalog with `cargo run -p xtask -- fixtures --verify` (also part
of `xtask check` and CI). The verifier fails on digest mismatch, unknown
license, path escape, or private-key material — those failure modes have unit
tests in `xtask/src/fixtures.rs`.

## Deterministic properties

Time, path, and hash logic uses fixed fixtures and property tests so that
legal-enough behavior is checked across edge classes: DST overlaps,
nonexistent local times, missing year/timezone, conversion overflow,
Chromium/FILETIME/Firefox epoch units, invalid UTF-8 names, and
Unicode-distinct names.

## Running everything

- `cargo run -p xtask -- check` — the battery CI runs (fmt, clippy, tests,
  wgpu feature build, fixtures, policy).
- `cargo test --workspace --locked` — tests only.
- Focused task checks use the plan's listed commands (for example P1.1:
  `cargo test -p ghosttrace-core --test time_semantics --test native_paths --locked`).

`cargo nextest` may replace the default test runner once introduced, but the
plain-Cargo quickstart must keep working (plan Section 16).

## What testing does not claim

Passing tests do not certify a parser's forensic interpretation of a real
artifact, screen-reader conformance, or performance on a particular machine.
Those claims are made only against the documented evidence for the verified
targets in `docs/releases.md` and release notes.
