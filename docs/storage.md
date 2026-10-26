# Case storage

This document describes the case storage design implemented in P1.2
(`ghosttrace-core/src/storage/`, `src/service.rs`, `src/jobs.rs`). It is the
companion to `docs/evidence-model.md` (what is stored) and
`docs/timestamps.md` (how times are represented).

## Directory layout

A case is a directory named `<case-id>.ghosttrace-case`, created owner-private
(Unix `0o700`; Windows ACL hardening arrives in P9):

```
<case-id>.ghosttrace-case/
├── case.toml            # label, display zone, description (investigator config)
├── case.sqlite          # the fixed-schema case database (WAL mode)
├── objects/sha256/ab/   # content-addressed captured objects (two-level)
├── staging/<job-id>/    # in-flight work only; published objects never live here
├── manifests/           # manifests referenced by packages (P3.2)
├── reports/<export-id>/ # generated report artifacts
├── diagnostics/         # logs and pre-migration backups
└── locks/               # writer lock coordination
```

Case creation is **exclusive**: re-creating an existing case is refused rather
than overwritten, because storage is evidence.

## Writer ownership

- Exactly one **dedicated writer thread** owns the write connection per case
  per process. A second writer for the same case is an application bug and
  fails fast (`storage/writer.rs`); cross-process concurrent writers are
  serialized by SQLite's WAL write locks and fail at first write.
- Batches are submitted to a **bounded** queue (`sync_channel`, depth 64 by
  default): a saturated writer applies backpressure to the caller instead of
  buffering unbounded work.
- Every batch is one transaction: an interruption (an FK violation, an I/O
  error) rolls the **whole** batch back. A completed run is never a completed
  partial batch (`tests/case_storage.rs`).
- Facts use `ON CONFLICT DO NOTHING` (replays are no-ops); mutable job
  checkpoints use `ON CONFLICT DO UPDATE`.
- Readers open their own **read-only** connections with short transactions and
  never write, and keep working while the writer holds ownership
  (`tests/writer_concurrency.rs`).

Pragmas at open: `foreign_keys=ON`, `journal_mode=WAL`, `synchronous=FULL` for
integrity-sensitive writes, and a measured 5 s `busy_timeout`.

## Schema and migrations

- `migrations/0001_case.sql` is the base schema (all Section 5 records:
  cases, acquisitions, coverage, evidence objects, file observations, parse
  runs, raw observations, events, event times, entities, relationships,
  analysis runs, findings, annotations, exports, job checkpoints, migrations).
- Migrations are sequential and **checksummed**. Each applied step records
  version, name, and SHA-256 of its exact SQL in `schema_migrations`;
  `PRAGMA user_version` mirrors the applied set.
- Recorded history must match the embedded migrations on every open. A
  mismatch (edited migration) or a recorded migration unknown to this
  application is rejected as schema-incompatible — never silently skipped.
- A case whose schema is **newer** than this build supports is rejected, never
  downgraded.
- Before an existing case's schema is modified, a validated backup is required
  (`storage/backup.rs`): a consistent SQLite online backup (sees committed WAL
  data) is written to `diagnostics/`, fsynced, SHA-256 hashed, and re-opened
  read-only for `integrity_check` plus schema verification. **If the backup
  fails, the migration aborts before any schema change.** A new empty case
  needs no pre-creation backup.

## Query contract

`domain/query.rs` defines the shared request/pages (structured fields only —
arbitrary SQL is never exposed to front ends):

- `EventQuery` — active revision, kind/host filters, optional time bounds,
  page limit (clamped to the documented maximum), and a keyset cursor.
- `EventPage` — rows plus the next cursor and the case display zone.
- Ordering is a total order: chosen time (seconds, nanoseconds), then event id.
  Identical-time events paginate **without skips or duplicates**, and the
  keyset cursor resumes strictly after the last row.
- Events with no chosen time are never silently dropped: they are reachable
  through the explicit unresolved view (`unresolved_only`), which orders by
  event id. The displayed status is preserved (`resolved`, `ambiguous`,
  `unresolved`, `invalid`) so uncertainty stays visible in every front end.

## Jobs and recovery

`job_checkpoints` stores job state (`queued`, `running`, `completed`,
`partial`, `cancelled`, `failed`), input identity + digest, adapter version,
config digest, committed locator, and exact integer counters.

At case open, jobs found still `running` are reported as **recoverable**
(`service::CaseOpenReport::recoverable_jobs`) — they are never auto-marked
completed. Resume requires the checkpointed input identity and digest to match
(`jobs::JobCheckpoint::can_resume`), and resume continues strictly after the
committed locator.

## Startup diagnostics

Opening a case collects and reports what the linked SQLite runtime actually
is (`storage::StorageDiagnostics`): library version, foreign-key enforcement,
journal mode (WAL), `synchronous`, and page size — recorded, never assumed.
`docs/releases.md` carries the platform evidence these are checked against.
