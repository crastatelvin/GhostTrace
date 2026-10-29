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
| TUI state/terminal safety | Key/action transitions, shared query identifiers, escaped control bytes, restoration on exit/error/unwind, no ANSI in pipes | `crates/ghosttrace-cli/tests/tui_actions.rs`, `terminal_safety.rs` (P7) |
| Worker protocol/limits | Frame bounds, record validation, handshake and path refusals, crash/hang/garbage/oversize/cancel, record limits, and worker-vs-in-process output equality | `crates/ghosttrace-core/tests/worker_protocol.rs`, `worker_crash.rs`; `crates/ghosttrace-cli/tests/worker_limits.rs` (P8.2) |
| EVTX ingestion | Real Windows logs: provider/channel/version mapping, exact payload record locators, UTC logging + payload occurrence time, unreadable chunks, truncated chunk areas, header-less refusal | `crates/ghosttrace-core/src/ingest/evtx.rs` unit tests, `tests/evtx_import.rs` (P8.1) |
| Adversarial/fuzz | Oversize, truncation, hostile payloads, recovery from injected failures | `crates/ghosttrace-core/tests/fuzz_targets.rs` (bounded proptest), `crash_recovery.rs`, `hostile-inputs` fixtures |
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

## Bounded fuzz targets (P10.1)

`crates/ghosttrace-core/tests/fuzz_targets.rs` treats the time, native-path,
manifest, CSV/display, and worker-frame boundaries as fuzz targets. It uses the
already-pinned `proptest` dev-dependency with a fixed case count, so it runs on
the stable toolchain in the ordinary test battery and any failure is saved as a
deterministic regression.

A separately pinned nightly/libFuzzer harness was considered and rejected for
the release gate: it would add a second toolchain to CI and a corpus artifact to
maintain, while the properties above are pure functions that proptest already
exercises across arbitrary inputs. If a future parser gains a large stateful
surface, add a dedicated fuzz crate then, pinned and run on a schedule rather
than blocking stable builds.

The target already found one real fault: the Windows native-path decoder
silently truncated non-ASCII characters (`é` became U+00E9) instead of
rejecting a malformed ASCII interchange encoding. The decoder now rejects
non-ASCII literal characters, and `non_ascii_windows_encoded_text_is_rejected_not_truncated`
is the regression.

## Failure injection (P10.1)

`crash_recovery.rs` covers the publish boundaries:

- an unwritable report/package/backup output fails and leaves no directory that
  looks complete (skipped under a root CI user, where mode bits cannot deny
  writes);
- abandoned `.part` staging is removed, not trusted;
- an impossible free-space reserve is refused before copying;
- a truncated database is refused on reopen, not opened as an empty case;
- a corrupted stored object makes manifest verification fail.

Disk-full is modelled by the reserve check plus unwritable output. A filesystem
that fills during a copy still fails safely (staging is removed) but reports a
storage error rather than `ResourceLimit`; that distinction is disclosed in
`docs/storage.md`.

## Dependency review (P10.1)

`cargo run -p xtask -- deps` reads `cargo metadata` and fails if any package
declares no license or a license string that is not on the reviewed allowlist
in `xtask/src/deps.rs`. It also reports duplicate crate versions. When
`cargo-audit` is installed it runs the RustSec advisory check; otherwise it
prints `not_installed` instead of pretending the check ran. The scheduled
`.github/workflows/security.yml` installs `cargo-audit` and runs the same
command weekly. The first recorded run (2026-10-29) reported 0 vulnerabilities
and 32 transitive duplicate crate versions for review.

## Platform matrix status

| Target | Status in this revision | Evidence |
|---|---|---|
| Linux x86_64 | Tested | Full battery on Linux 6.17 / Ubuntu, X11 and Wayland GUI smoke, rootless Xwayland caveat recorded in `docs/releases.md` |
| Windows x86_64 | Not run | `cfg(windows)` safety modules build-gated only; no Windows host available here |
| macOS arm64 | Not run | `cfg(target_os = "macos")` modules build-gated only; no macOS host available here |
| Linux arm64 / macOS x86_64 | Not run | Additional targets after native CI evidence |

Build success alone is not support. The Windows/macOS safety modules, NVDA,
VoiceOver, Windows Terminal, and macOS terminal smoke checks remain release-gate
items in P10/P11; until they run, the documentation describes only Linux x86_64
as tested.

## Scale corpora and benchmarks (P10.2)

`xtask scale generate` writes a deterministic corpus and records exact counts
and SHA-256 digests in `corpus.json`; `xtask scale run` re-verifies that
manifest before timing anything, so a benchmark number always names the bytes
it measured.

```bash
# 1,000,000 events, 200 small files, no large file
cargo run --release -p xtask -- scale run \
  --output /tmp/opencode/scale-1m --events 1000000 --files 200 --iterations 20

# large-file capture throughput (64 MiB)
cargo run --release -p xtask -- scale run \
  --output /tmp/opencode/scale-large --events 1000 --files 10 \
  --large-file-bytes 67108864 --iterations 5 --skip-graph
```

`crates/ghosttrace-core/benches/queries.rs` holds Criterion microbenchmarks for
the first page, histogram, phrase search, and event detail on a 20,000-event
case. Run them with `cargo bench -p ghosttrace-core --bench queries`. The
recorded baselines and their limits are in `docs/performance.md`.
