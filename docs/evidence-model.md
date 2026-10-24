# Evidence model

This document defines GhostTrace's records and ownership rules. The
implementation lives in `ghosttrace-core/src/domain/`; the storage mapping
arrives with the case schema in P1.2.

## Golden rules

1. **Raw is immutable.** Captured bytes and raw observations are never edited
   in place. New parsing, corrected timezone assumptions, changed rules, or
   edited notes produce new runs/revisions; previous results stay available
   for comparison and old-report reproduction.
2. **Interpretations are versioned.** Raw observation → normalized event →
   analysis run → finding → annotation revision. Each layer references the
   one below so provenance always walks back to records.
3. **No silent success.** An unknown timestamp, a missing hash, an incomplete
   traversal, or a parser failure is reported, never averaged into a
   successful result.
4. **Nothing is invented.** Locators reflect what a parser actually supports;
   a logical row locator discloses that no byte range exists.

## Records

| Record | Meaning | Key fields |
|---|---|---|
| Case | investigator workspace | ID, label, schema version, creation instant, display timezone, description |
| Acquisition | what was attempted, under which conditions | method (protected/live), claimed source, roots/exclusions, link policy, state (queued/running/completed/partial/cancelled/failed) |
| Evidence object | captured bytes or a captured non-file observation | native path (exact), kind, byte length, **digest status**, SHA-256, store location |
| File observation | filesystem fact at capture time | scoped native identity, size, named raw timestamps, link target, observation time |
| Raw observation | what a parser extracted | record locator, raw field values, evidence reference |
| Event | normalized interpretation | kind, summary, times, host claim, observation references, revision |
| Annotation revision | analyst opinion/history | target ID, author label, timestamp, previous revision, text/tags/disposition |

Case is a workspace, not proof of source identity: the acquisition's claimed
source is investigator-recorded, and cross-snapshot identity is only ever a
*candidate* (see `docs/plans/2026-10-23-ghosttrace-master-plan.md` §6).

## Digest status

`DigestStatus` has four values and one invariant:

- `Complete` — full-content digest over successfully captured bytes; the only
  status that may present a verification. The constructor
  `EvidenceObject::captured` requires a SHA-256, so `Complete` and "no digest"
  cannot coexist.
- `Partial` — digest over incomplete bytes; never verification.
- `Failed` — hashing failed or bytes changed during capture.
- `NotApplicable` — non-file observation.

A partial digest never becomes a verified full digest; the captured hash
verifies the stored copy, not a later source read (checked in P2.2).

## Native identity

Unix device/inode and Windows file IDs are **scoped by acquisition
volume/host** (`NativeIdentity::scoped_identity`). Hardlinks create multiple
path observations; identifier reuse makes cross-snapshot continuity a
candidate, never an assertion. Symlink targets and reparse metadata are
captured without being followed. Path identity is byte-exact: Unicode
normalization, case folding, and lossy string conversion never merge names
(`domain::path`).

## Record locators

| Source | Locator | Honesty rule |
|---|---|---|
| Text/JSONL | byte offset + length + line | exact |
| Journal export | object ID + byte range + boot ID + retained repeated fields | exact |
| Browser SQLite | object/package ID, table, primary key, schema fingerprint | **logical**, disclosed as such |
| EVTX | object ID + chunk/record location + channel/provider + record ID (scoped to source) | exact where the parser exposes it |
| Filesystem | acquisition path entry + handle-based metadata | observation interval disclosed |

When a parser cannot supply a byte locator, the strongest supported logical
locator is kept and the limitation is disclosed. Offsets are never invented.

## Idempotency

The idempotency key for a raw record is:
**acquisition ID + evidence object ID + parser version/config + exact record
locator**. Re-importing the same already-completed artifact in the same run
does not duplicate it. Importing the same bytes as a new acquisition preserves
a distinct provenance chain. Content deduplication may reuse object bytes,
never acquisition identities (enforced when the storage idempotency keys
exist in P1.2).

## Timestamps

See `docs/timestamps.md`. Raw values keep their field name, epoch, unit, and
declared precision; statuses (`Resolved`/`Ambiguous`/`Unresolved`/`Invalid`)
carry uncertainty instead of hiding it.
