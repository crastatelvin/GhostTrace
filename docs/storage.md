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
- `0003_search` (P4.4) is additive: an FTS5 external-content index over event
  summary/kind/host text, an insert trigger, recorded run assumptions, and a
  rebuild for cases created before it.
- `0004_analysis` (P5.1) is additive: `events.evidence_id` and
  `events.locator_identity` link an event to its source record (events
  recorded before the migration keep `NULL` and are reported, never
  back-filled by guesswork), an entity lookup index, a unique relationship
  pair index, and relationship lookup indexes.

## Search index

- `events_fts` is an **external-content** FTS5 table over `events`: the index
  stores terms, never a second copy of event text. A rebuild can therefore
  never lose or change a recorded fact, and `events` remains the only place
  event text lives.
- A trigger inserts on `events`. Events are immutable facts (no updates or
  deletes) and the writer's `ON CONFLICT DO NOTHING` makes replays skip the
  insert, so the trigger alone keeps the index in step. `ghosttrace`
  can rebuild the index through the dedicated writer
  (`CaseWriter::rebuild_search_index`), which is the supported repair path.
- Tokenizer is `unicode61` (word/phrase search). Raw field values, binary
  values, and evidence bytes are **not** indexed; they are reached through the
  timeline and event detail.
- The index is derived, so `xtask`/operator maintenance never needs to reason
  about whether an index row is "authoritative": `events` is.

## Revisions (one parse run, one revision)

- Every import records a **parse run**, and that run id is the revision label
  of the events it produced. Re-importing the same object with different time
  assumptions (for example a different RFC 3164 year or zone) records a **new
  run** — a new revision — and leaves the earlier events untouched.
- A revision is therefore the unit of reproducibility: a report pins one
  revision, and building the same report again produces the same timeline.
- `timezone` and `year` never silently replace a previous interpretation: both
  revisions stay listed (`storage::search::list_revisions`) with the
  assumptions each one recorded (`parse_runs.assumptions_json`), and the
  operator chooses which to read.

## Entities and relationships

- `entities` rows are derived, never authoritative facts about the world.
  Their ids are deterministic over kind, scope, and raw form, so rebuilding a
  run inserts the same rows. Scope rules live in `docs/architecture.md`.
- `event_entities` links an event to each identity it recorded. The lookup
  index `event_entities_by_entity` serves the entity-neighbourhood direction;
  the primary key serves event detail.
- `relationships` holds one row per rule version per canonical endpoint pair
  (`relationships_pair` unique index). `support_json` names the matching
  field and the supporting event ids; `strength_basis` states why the edge is
  observed or only a candidate. Replaying correlation adds nothing.
- `query_relationships` is the only read path. It is keyset ordered by
  relationship id, bounded by page size, and filterable by endpoint, kind, and
  rule. No caller builds relationship SQL from input.

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
- `storage/search.rs` adds full-text search over the same `EventQuery`
  filters, ordered and paged identically. The operator's search text is
  validated against a documented grammar and passed to FTS5 as a **bound
  parameter**: no operator text ever becomes SQL.

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

## Findings, review history, and saved views

- `analysis_runs` holds one row per (revision, rules version, config digest).
  `counts_json` records every rule's status, reason, findings, considered and
  excluded counts, and truncation flag, so a run that decided nothing is still
  explainable. Replaying the same inputs rewrites the same run id.
- `findings` holds one row per deterministic finding id, with the rule version,
  sorted supporting event ids, exact predicates, severity, rationale, and
  alternatives. Indexes `findings_by_run_rule` and `findings_by_rule` serve the
  two read directions. `findings.disposition` is the evaluator's initial
  `undismissed` value and is never rewritten by analysis.
- `annotation_revisions` is append-only: each row names `previous_revision`,
  its author label, bounded text, a JSON tag list, and an optional disposition.
  An edit whose `previous_revision` is no longer the tip fails with `conflict`
  (exit `1`) and writes nothing. The newest non-null disposition for a target
  is the current one; findings are read with that value overlaid, so
  re-analysis reports the analyst's state.
- `saved_views` stores a name and a `filter_json` value set. The JSON is parsed
  with `deny_unknown_fields` on read as well as write: a view from a build with
  a different field set fails with `invalid_request` instead of silently
  dropping a criterion.
- Migration `0005_findings` is additive: `analysis_runs.counts_json`,
  `raw_observations.mapped_fields_json`, the finding/review indexes, and
  `saved_views`. `mapped_fields_json` keeps adapter interpretation next to, not
  inside, the recorded raw fields; `NULL` means "mapped nothing", never
  "mapped and empty".
