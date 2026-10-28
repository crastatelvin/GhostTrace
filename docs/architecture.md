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
the fixed mapping, (b) the three tested sshd/sudo message patterns, and (c)
well-framed journal entries. RFC 3164 year and zone are never inferred: absent
operator declarations leave times unresolved, DST overlaps carry both
candidates, and a December→January sequence is ambiguous.

The journal adapter is byte-oriented because the export stream is binary and
fields repeat. It keeps ordered `[name, value]` pairs (binary values as
`{"binary_hex": …}`), skips an oversized or truncated entry whole with a
diagnostic, and preserves `__CURSOR` verbatim. Realtime timestamps alone
position an event; monotonic values are stored with clock domain
`boot:<_BOOT_ID>` and `journal::compare_boot_times` refuses cross-boot order.
Native `.journal` files are out of scope: `journalctl -o export` is an external
acquisition step whose output is captured as an ordinary object.

Browser packages (P4.3) add one package step before parsing: the captured main
database and its `-wal`/`-shm` sidecars are digest-verified, copied into the
case staging tree, and opened only there. The private copy is read-write once so
SQLite can apply a committed WAL, then `query_only`; `trusted_schema=OFF`,
`cell_size_check=ON`, SQLite limits, and a 30-second progress deadline guard
fixed `SELECT` statements. Views and virtual tables are rejected before any
adapter query, the schema contract chooses `browser.chromium` or
`browser.firefox`, and a main database in WAL mode without its WAL is reported
as a partial package with `wal_missing` rather than completed silently. Raw
observations use logical row locators (`table:<table>:rowid:<id>`) and keep all
original values; only visit rows and Chromium download metadata become events.

## Analysis section (P5.1)

Entity resolution runs over one parse run at a time
(`CaseSession::build_entities(run_id)`), reading events plus the evidence
object and the raw observation each event points at. Migration 0004 records
that link (`events.evidence_id`, `events.locator_identity`); events imported
before it keep `NULL` and are counted as `events_without_source` instead of
being given an invented source.

Identity is scoped before it is compared. A scoped identity is an unambiguous
JSON component list, so a value can never bleed from one field into another:

| Kind | Scope components | What it claims |
|---|---|---|
| `host` | `["host","claim",<name>]` | the host the record claims, never verified |
| `user` | `["host",<host>,"user",<name>]` | the same username on another host is a different entity |
| `ip` | `["host",<host>,"ip",<addr>]` | the address as claimed by that host |
| `process` | `["host",<host>,"process",<boot or "no-boot">,<pid>]` | a PID is meaningless without its host and boot |
| `path` | `["acquisition",<id>,"path",<path>]` | path identity never crosses an acquisition |
| `digest` | `["sha256",<hex>]` | equal bytes are equal bytes, globally |

Only documented adapter fields become entities: `user`/`username`/`account`/
`user.name`, `src_ip`/`remote_ip`/`source_ip`/`ip`, `pid`/`_PID`/`process_id`,
`_BOOT_ID`/`boot_id`/`boot`, `path`/`current_path`/`target_path`, and
`sha256`/`sha256_hex`/`hash` (exactly 64 hex characters). Journal `[name,
value]` pair arrays and JSON objects are both read. Free text is never parsed
into an identity, so a log message cannot invent a user or an address.

Correlation (`CaseSession::correlate`) derives one-hop edges and writes them
through the writer as insert-or-ignore facts:

| Rule | Version | Kind | Basis |
|---|---|---|---|
| `correlate.digest_equal` | 1 | observed | equal complete SHA-256 bytes, not a proven copy, move, or common origin |
| `correlate.shared_ip` | 1 | candidate | same claimed IP on different scopes (NAT, DHCP, proxying) |
| `correlate.shared_basename` | 1 | candidate | same final path component on different scopes |

Each edge stores its rule id, rule version, matching field, supporting event
ids, and the strength rationale. Endpoints are stored in canonical order and a
unique index keeps one edge per rule version per ordered pair, so replaying
correlation explains the same edge instead of duplicating it. There is no
transitive closure: two hops are two claims, not one.

Work is bounded three ways: a bucket larger than `max_bucket_entities`
(default 32) is skipped and counted, `max_pairs` (default 50 000) caps pair
comparisons, and `max_edges` (default 5 000) caps derived edges. Candidate
rules compare only entities whose event times are within `window_seconds`
(default 3 600); an entity with no resolved time is counted as
`unsupported_time` and never treated as inside or outside the window.
`query_relationships` is a keyset read (page size clamped to 1..=1 000)
filterable by endpoint, kind, and rule.

## Findings and review section (P5.2)

`CaseSession::analyze` evaluates five compiled rules over one parse run and
records an `analysis_runs` row plus its findings. There is no script engine, no
plugin loading, and no free-form expression: a rule is Rust code with a fixed
id and version, and its parameters are a validated typed value set.

| Rule | Version | Severity | Basis |
|---|---|---|---|
| `auth.fail_then_success` | 1 | medium | N failures for the same host/user/service followed by a success within a window |
| `process.download_then_execute` | 1 | medium | a download and an execution naming the same path or digest inside a window |
| `file.hash_changed_metadata_equal` | 1 | low | two captures of one path with equal size and source mtime but different full SHA-256 |
| `time.clock_discontinuity` | 1 | info | realtime and boot-monotonic time disagree across two samples in one clock domain |
| `activity.outside_declared_hours` | 1 | info | activity outside an investigator-declared schedule |

Every finding stores the rule id and version, the sorted supporting event ids,
the exact predicates that held (as recorded values), the severity, a
rationale, and the alternatives that remain plausible. Severity is a handling
priority; no field expresses a probability of maliciousness, and no output is
allowed to describe one. `Finding` has no numeric score at all.

Rules read only documented adapter fields, through the mapped fields the
adapter recorded (`raw_observations.mapped_fields_json`) and then the raw
fields. Free text is never parsed into an account, path, or address, so a log
message cannot manufacture a finding input.

Missing prerequisites are reported, never guessed. A rule with nothing to
compare returns `not_evaluated` with a reason and the counts it did see
(`events_considered`, `excluded`). `activity.outside_declared_hours` is
disabled until a baseline is supplied; `process.download_then_execute`
reports `not_evaluated` when no execution event carries a path or digest.
Unresolved or ambiguous times are counted as excluded rather than ordered.

Identity is reproducible. `analysis_runs.id` is derived from the input
revision, the rules id/version, and the configuration digest; a finding id is
derived from the rule id/version, the revision, the config digest, the sorted
event ids, and the canonical predicates. Re-running the same inputs therefore
rewrites the same rows instead of accumulating near-duplicates, and a changed
parameter produces a distinct run.

Analyst state lives in append-only `annotation_revisions`, not on the finding
row. A note edit names the revision it supersedes; a stale name is a
`conflict` error instead of a silent overwrite. Dispositions (confirmed,
dismissed, commented) are read back as the newest recorded disposition, so a
new analysis run cannot destroy a dismissal and the evaluator's initial
`undismissed` row stays untouched.

Saved views (`analysis::views`) are named, validated filter values: optional
kind/host/source, validated search text, time bounds, the unresolved view, and
a bounded page limit. Unknown fields are rejected on write and on read, and a
stored view runs through the same `query_events`/`search_events` path as the
CLI, so a view can never become SQL.
