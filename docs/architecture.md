# Architecture

This document describes the implemented architecture and the reasoning behind
the load-bearing decisions. It tracks the phased plan
(`docs/plans/2026-10-23-ghosttrace-master-plan.md`); where they disagree, the
plan governs intent and this file describes what actually exists.

## Layers

```
Source (protected copy / acknowledged live source)
  → Capture      spec validation, no-follow traversal, coverage ledger (P2.1)
  → Copy/Hash    staging, streaming SHA-256, atomic publish (P2.2, below)
  → Case storage fixed SQLite schema, one writer, checksummed migrations (P1.2)
  → Ingest       bounded adapters, raw observations, versioned parse runs (P4.1, below)
  → Service      shared query contract for desktop, TUI, CLI (P1.2+)
  → Analysis     versioned revisions, rules, reversible review (P5)
  → Reports      versioned JSON/HTML export, manifest verification (P3.2, below)
  → Packages     signed distribution, SBOM/provenance (P9/P11)
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

## Copy, hash, and recovery section (P2.2)

### Publication protocol

`capture/copy.rs` implements the plan's protocol in order, and every step
fails closed:

1. **Open** with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` — a link is
   never followed, and a path that became a FIFO after traversal cannot hang
   the worker.
2. **Identity check** against the device/inode the walker observed. A source
   replaced between observation and open is `unstable`, not captured.
3. **Size cap** — files above `max_file_bytes` are recorded as `excluded` and
   never read.
4. **Reserve** — a 64 MiB free-space margin must remain; otherwise the run
   stops with `ResourceLimit` instead of filling the disk.
5. **Stream once** into a private `0600` staging file while hashing the same
   bytes (one 64 KiB buffer; memory never scales with file size).
6. **Sync** the staging file, then **re-check** the descriptor (fstat) and the
   path (lstat). Any identity, size, or mtime change discards staging and
   records `unstable`; a vanished path records `vanished`.
7. **Publish** by atomic rename to `objects/sha256/ab/<digest>` and fsync the
   bucket. Existing identical content is reused (`deduplicated`), never
   overwritten with different bytes.

A cancelled or failed copy removes its staging file and returns no digest, so
a partial read can never be mistaken for a verified full-content hash. Up to
four workers copy in parallel; the walker runs before copying, so memory is
bounded by the entry cap rather than the file count.

### Manifest v1

`integrity/manifest.rs` writes `manifests/<acquisition>.json` with format
`ghosttrace-manifest/1`: method, tool version, link policy, roots, coverage
counts, and one entry per object (ID, root label, encoded relative path, exact
byte length, SHA-256, store subpath, hardlink alias). Writing is atomic
(private temp → sync → rename → directory sync) and formatting is stable.
`verify_objects` re-hashes the *stored* copies; it never reads the source
again, so later source changes cannot make a case look verified.

### Job state and recovery

The acquisition row and its `job_checkpoints` record are written before any
bytes move and settled after the manifest exists. `completed` means every
file the walker offered was published and the ledger has no
inaccessible/unstable/vanished/unobserved entries; `partial` records a copy
cap, a copy failure, traversal caps, or such ledger gaps; `cancelled` keeps
unstarted tasks as explicit `unobserved` rows. A `running` checkpoint found
on reopen stays recoverable (P1.2), never auto-completed.

`inspect_recovery` reports two leftovers without touching them: abandoned
`staging/*.part` files (our own incomplete copy) and published objects with no
`evidence_objects` reference (a crash between rename and commit). The
operator decides to adopt or quarantine; the tool never deletes published
bytes.

### Capture metadata events

Each observed path also produces a `file.observed` event in parse run
`capture.metadata.v1`, timed with the *application* clock (`occurrence_time`,
host domain) — explicitly tool-observation time, not a source timestamp.
Source timestamps arrive with the format parsers (P4+).

## Storage section (P1.2)

`docs/storage.md` holds the detailed rules. Summary: a case is a private
directory `*.ghosttrace-case` with a fixed-schema SQLite database; one
dedicated writer thread owns writes through a bounded queue, committing whole
batches or nothing; readers are separate read-only connections; migrations are
sequential, checksummed, and preceded by a validated online backup; the query
contract is a total order over (chosen time, nanos, event id) with an explicit
unresolved view.

## Reports and verification section (P3.2)

`ghosttrace verify` re-reads a manifest from disk and re-hashes every object it
references. The manifest is parsed twice on purpose: once with a visitor that
rejects duplicate JSON keys anywhere in the document, then with the typed
`ManifestV1` shape. References are validated before any file is opened —
duplicate object IDs/paths and any `store_subpath` outside
`objects/sha256/<bucket>/<hex>` are rejected, so a hostile manifest cannot make
the verifier read outside the case store. Missing or differing bytes fail
closed; recorded coverage gaps are reported, not treated as tampering.

`ghosttrace report` builds `ReportV1` (`ghosttrace-report/1`) from recorded rows
only: case identity and display timezone, acquisition method/roots/state,
coverage counts plus a bounded gap list, every captured object's full SHA-256,
the acquisition's application-clock events, provenance, and fixed limitation
statements. The JSON rendering is full fidelity. The HTML rendering is a
separate, deliberately dumb presentation layer: inline CSS only, no scripts, no
links, no remote resources, a `default-src 'none'` CSP, HTML escaping for every
value, and `\u{...}` escapes for C0/C1 and Unicode bidi/format controls.

Publication stages both files in a private directory inside the output folder,
fsyncs them, renames the directory into place, and refuses to overwrite an
existing report ID. A failure removes the staging directory, so an incomplete
run never leaves something that looks like a finished export.

`xtask package` is the early packaging path: it archives an already-built
binary with licences, docs, `--help` output, sample data, and a `build-info.json`
inventory (target triple, rustc, commit, per-file SHA-256), then writes the
archive digest. It does not build, sign, or upload anything.

## Ingest section (P4.1)

`ingest::run_import` reads only the stored copy of a captured object. It
re-hashes that copy against the recorded SHA-256 before creating a run, so a
tampered object produces `integrity_mismatch` instead of plausible events.

The adapter is chosen by a bounded signature prefix (`{`/`[` for JSONL, `<PRI>1 `
for RFC 5424, other `<PRI>` for RFC 3164) unless the operator declares one. Both
the detected and the declared format are reported, and `parse_runs.parser_id`
records which adapter actually ran. The run id is deterministic over evidence
identity, adapter id/version, and a digest of the effective bounded
configuration, so replays are no-ops while any mapping change creates a new
revision.

Records stream through a bounded reader: a record never buffered past the byte
limit is consumed to its newline and reported (`record_too_large`); invalid
UTF-8, malformed JSON/syslog headers, wrong mapped field types, and unparseable
times become stable diagnostics rather than silent drops. Batches commit every
500 records; cancellation is checked between records and recorded as a
`cancelled` run.

Every parsed record is stored as a raw observation with a byte-range locator and
its original fields. Events are emitted only for (a) valid JSONL objects under
the fixed mapping and (b) the three tested sshd/sudo message patterns. RFC 3164
year and zone are never inferred: absent operator declarations leave times
unresolved, DST overlaps carry both candidates, and a December→January sequence
is ambiguous.
