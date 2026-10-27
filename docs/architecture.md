# Architecture

This document describes the implemented architecture and the reasoning behind
the load-bearing decisions. It tracks the phased plan
(`docs/plans/2026-10-23-ghosttrace-master-plan.md`); where they disagree, the
plan governs intent and this file describes what actually exists.

## Layers

```
Source (protected copy / acknowledged live source)
  → Capture      spec validation, no-follow traversal, coverage ledger (P2.1)
  → Copy/Hash    staging, streaming SHA-256, atomic publish (P2.2)
  → Case storage fixed SQLite schema, one writer, checksummed migrations (P1.2)
  → Parsers      bounded workers, raw observations, journal/EVTX/browser adapters (P4/P8)
  → Service      shared query contract for desktop, TUI, CLI (P1.2+)
  → Analysis     versioned revisions, rules, reversible review (P5)
  → Packages     redacted reports, exact-byte manifests, signatures (P3.2/P9)
```

The core library (`ghosttrace-core`) holds every layer above "source". Front
ends (`ghosttrace-desktop`, `ghosttrace-cli`, and later the TUI) share the same
service and query types; none of them talks to SQLite directly.

## Capture section (P2.1)

### Spec validation

A `CaptureSpec` (plan Section 6) names roots, a symlink policy, depth/entry
caps, a file-size cap, and the case directory. Validation happens **before**
anything touches disk:

- a root that does not exist is rejected (`capture_root_missing`);
- a root that is the case store, inside it, or contains it is rejected
  (`capture_overlaps_case_store`) — the case's own database and objects must
  never become evidence;
- duplicate roots are rejected (`capture_duplicate_root`);
- `follow_symlinks = true` is rejected (`capture_follows_symlinks`) — capture
  is no-follow by design, recorded per link.

Overlap logic is exact byte-prefix comparison (`/a/b` is inside `/a`, `/a/bc`
is not), never canonicalization, because canonicalization follows the symlinks
we are explicitly refusing to follow.

### Traversal

The Unix walker (`capture/unix.rs`):

1. classifies every entry with `symlink_metadata` — nothing is followed;
2. preserves **native relative paths as exact bytes** (invalid UTF-8 names and
   Unicode-distinct names never merge);
3. observes object identity (device + inode) per entry, scoped to the
   acquisition, to detect hardlinks: the same identity at a second path is an
   alias observation of one set of bytes, never a duplicate capture;
4. records identity repetition for directories as a loop guard;
5. reads FIFOs, sockets, and device nodes **never** — they are `unsupported`;
6. respects depth and entry caps, recording the truncation point as
   `unobserved` rather than ending silently;
7. maps permission-denied to `inaccessible` and vanished entries to `vanished`,
   each with a stable reason code, so an interrupted or partial traversal is
   honest evidence rather than an abort.

Permission behavior is exercised as an ordinary user; the test skips itself
under root and says so.

### Coverage ledger

Every path that was not fully captured produces a `CoverageOutcome`
(`capture/coverage.rs`): root-relative native path, depth, status, stable
reason code, and identity when observed. Statuses are `captured`, `excluded`,
`inaccessible`, `unstable`, `vanished`, `unsupported`, `unobserved`. Full rows
go to the `coverage` table (idempotent by acquisition + path key); the
in-memory `CoverageSummary` keeps bounded per-category examples (3 per
category, 32 total) so a pathological tree cannot exhaust memory while the
complete picture stays in the database.

### Platform status

Unix is the verified path. Windows capture (`capture/windows.rs`) is a
reviewed stub returning "not implemented yet" — the walker surface is
platform-uniform so the Windows implementation (NtCreateFile with
`FILE_FLAG_OPEN_REPARSE_POINT`, volume file IDs) has a defined home, but no
silent Unix behavior is claimed for it.

## Storage section (P1.2)

`docs/storage.md` holds the detailed rules. Summary: a case is a private
directory `*.ghosttrace-case` with a fixed-schema SQLite database; one
dedicated writer thread owns writes through a bounded queue, committing whole
batches or nothing; readers are separate read-only connections; migrations are
sequential, checksummed, and preceded by a validated online backup; the query
contract is a total order over (chosen time, nanos, event id) with an explicit
unresolved view.
