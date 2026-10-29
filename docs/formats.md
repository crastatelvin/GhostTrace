# Log format catalog (P4.1)

Only the adapters in this table exist, and only the listed rules produce
events. Anything else is preserved as a raw observation or reported as a
structured diagnostic; no adapter invents an event type, a year, or a zone.

| Adapter id | Version | Detected by | Produces events |
| --- | --- | --- | --- |
| `jsonl.fields` | 1 | first non-space byte `{` or `[` | every valid mapped object |
| `syslog.rfc5424` | 1 | `<PRI>1 ` prefix | only the tested auth messages below |
| `syslog.rfc3164` | 1 | `<PRI>` without a `1 ` version | only the tested auth messages below |
| `journal.export` | 1 | `__CURSOR=` or `__REALTIME_TIMESTAMP=` | every well-framed entry (`journal.record`) |
| `browser.chromium` | 1 | SQLite header, then a validated Chromium `urls`/`visits` contract | `browser.visit`, `browser.download` |
| `browser.firefox` | 1 | SQLite header, then a validated Firefox `moz_places`/`moz_historyvisits` contract | `browser.visit` |

`--format` overrides detection. The override is recorded: `parse_runs.parser_id`
is the declared adapter and the import result reports both `detected_format`
and `declared_format`. Detection never silently wins over an explicit choice.

## Run identity and replay

Each run has a deterministic id derived from the evidence object, adapter id,
adapter version, and a digest of the effective configuration. Re-importing the
same object with the same configuration is a no-op: raw observations are
unique per `(acquisition, evidence, run, locator)` and events are unique per
`(revision, event id)`. Changing any mapped field or bound creates a different
run and therefore a different revision to review.

### Revisions keep both interpretations (P4.4)

The run id is also the **revision label** of the events that run produced.
Importing the same RFC 3164 log twice with different `--year`/`--timezone`
values therefore records two revisions, each with its own events, instead of
replacing the earlier one:

```bash
ghosttrace import --case C --path logs/auth.log --format syslog-3164 --year 2026 --timezone UTC
ghosttrace import --case C --path logs/auth.log --format syslog-3164 --year 2026 --timezone Asia/Kolkata
```

Both runs stay listed with the assumptions each recorded, and both sets of
events stay readable. Reports pin one revision, so an already-published
report stays reproducible: `--revision RUN_ID` reproduces it exactly, and
pin-copying the same selection twice yields identical bytes.

## Bounds

| Bound | Default | Behavior when reached |
| --- | --- | --- |
| record bytes | 1 MiB (max 16 MiB) | `record_too_large` diagnostic, record skipped |
| records per import | 1,000,000 | `record_limit` diagnostic, run `partial` |
| stored diagnostics | 100 (count is exact) | `diagnostics_truncated` marker |

Batches commit every 500 records. Cancellation is checked between records; a
cancelled run is stored as `cancelled`, never as `completed`. For journal
exports the same byte bound applies to each entry and each binary field; an
entry over the bound is skipped whole, never partially stored.

## JSONL mapping

The mapping is a fixed list of field names and one of five fixed time formats.
There are no expressions, regular expressions, scripts, or path lookups.

| Setting | Default | Meaning |
| --- | --- | --- |
| `--time-field` | `ts` | field holding the record time |
| `--time-format` | `rfc3339` | `rfc3339`, `unix-seconds`, `unix-millis`, `unix-micros`, `unix-nanos` |
| `--message-field` | none | field used for the event summary (truncated at 512 bytes) |
| `--host-field` | none | field used as the claimed host (max 255 bytes) |
| `--kind-field` | none | field used as the event kind (non-empty, max 128 bytes) |
| `--default-kind` | `log.record` | kind used when no kind field is mapped |

Accepted, for `--time-format unix-seconds --kind-field kind --host-field host --message-field msg`:

```json
{"ts":1793095200,"kind":"file.read","host":"host-a","msg":"read report"}
```

Rejected or degraded, always visibly:

| Record | Result |
| --- | --- |
| `[1,2,3]` | `schema_mismatch`; no observation, no event |
| `{"msg":"no time"}` | event with `unresolved` time and `time_missing` diagnostic |
| `{"ts":"not-a-time"}` | event with `invalid` time and `invalid_time` diagnostic |
| `{"ts":"…","kind":42}` | raw observation kept; `schema_mismatch`; no event |
| `{"ts":"…"}` with `--kind-field kind` | raw observation kept; `schema_mismatch`; no event |
| a line that is not JSON | `malformed_record`; no observation, no event |
| invalid UTF-8 | `invalid_encoding`; no observation, no event |

Every parsed record is stored as a raw observation with its exact byte range
(`line:N:offset:O:len:L`) and the original field values.

## Syslog headers

RFC 5424 fields are preserved raw: priority, facility, severity, timestamp,
hostname, app-name, proc-id, msg-id, structured data (including repeated
elements and quoted spaces), and message. `-` is the RFC nil value. A nil or
malformed timestamp leaves the event time `unresolved`/`invalid`.

RFC 3164 fields are preserved raw: priority, facility, severity, the 15-byte
`MMM dd HH:mm:ss` stamp, hostname, tag, and message. Two things are missing from
the format itself:

- **No year** — supply `--year`; otherwise the time stays `unresolved`. The
  file mtime is never used to guess a year.
- **No timezone** — supply `--timezone` (IANA name); otherwise the time stays
  `unresolved` and the analyst workstation zone is never assumed.

With both supplied:

- a DST overlap produces `ambiguous` with both genuine candidates, earliest
  first;
- a nonexistent local time (DST gap) stays `unresolved`;
- a December→January sequence in file order is `ambiguous` between the declared
  year and the next year, because the header cannot decide it. GhostTrace does
  not silently roll the year.

## Tested authentication mappings

| Adapter input | Event kind |
| --- | --- |
| sshd `Accepted <method> for <user> …` | `auth.login_succeeded` |
| sshd `Failed password for [invalid user] <user> …` | `auth.login_failed` |
| sudo `… COMMAND=…` | `auth.sudo_command` |

The summary names the method, user, and source address when present. Any other
message is stored as a raw observation with no event, including messages that
only look similar. Adding a mapping requires a test next to these.

## Journal export (systemd)

GhostTrace parses the **export stream** produced by
`journalctl -o export`, not native `.journal` files. The export is an external
acquisition step: run it on the source host or offline against a mounted image,
store the resulting bytes as an ordinary captured object, then import that
object. No `journalctl` process is started by GhostTrace, and parsing never
requires the source host to be reachable.

The format is binary and order-sensitive, so the raw observation for an entry
is an **array of `[name, value]` pairs**, not a JSON object:

```json
[["__CURSOR","s=abc;i=1"],["MESSAGE","first"],["MESSAGE","second"],
 ["BINARY",{"binary_hex":"666f6f0a6261720007"}]]
```

- Repeated fields keep every value in source order (`MESSAGE` above appears
  twice); nothing is collapsed into one map entry.
- Text fields are stored as strings when the value is valid non-control UTF-8
  (TAB allowed). Binary fields are always `{"binary_hex": "..."}`, even when
  the bytes happen to be printable, so the format's distinction survives.
- `__CURSOR`, `__SEQNUM`, `__SEQNUM_ID`, and unknown `__`-prefixed fields are
  preserved as ordinary raw fields; nothing is inferred from them.
- An entry whose 64-bit length or data ends early produces `truncated_field`;
  an entry or field past `--max-record-bytes` produces `record_too_large` and
  is skipped whole. A skipped entry is never partially stored.
- A framing error reports `malformed_field` and resynchronises at the next
  blank-line boundary.

### Time

`__REALTIME_TIMESTAMP` (microseconds since the Unix epoch) is the only value
that can position an event on the timeline. `__MONOTONIC_TIMESTAMP` is stored
as a second named time with clock domain `boot:<_BOOT_ID>`; it is never
converted to wall-clock time. `compare_boot_times` returns an order only when
both values share the same boot ID, so values from different boots can never
be ranked or correlated by accident.

- No realtime value: `time_missing`, the event is `unresolved` with no chosen
  instant, and the monotonic value (if any) stays boot-scoped.
- Monotonic value without `_BOOT_ID`: `invalid_time`, `unresolved`, clock
  domain `unknown`.
- Unparseable realtime value: `invalid_time`, `invalid`.

## Browser history packages (Chromium and Firefox)

A browser package is a captured main SQLite database plus, when present, its
captured `-wal` and `-shm` sidecars. The adapter is selected by the SQLite
header and then by a validated contract; the schema decides
`browser.chromium` vs `browser.firefox`. `--format browser` declares the
detection step, but the schema is still validated before anything is read.

Package rules:

- The evidence object is re-hashed, then each member is copied to a private
  directory under the case `staging/` tree. Every copied member is re-hashed
  against its captured digest. Only the private copy is opened; the captured
  originals are never modified. The private copy is deleted when the parse
  ends, success or failure. No logical backup or derived database is produced,
  so there is no derived backup relationship to preserve.
- The private copy is opened read-write once so SQLite can apply a committed
  WAL, then switched to `query_only`. `trusted_schema=OFF` and
  `cell_size_check=ON` are set before schema inspection; SQL length, column,
  expression-depth, compound-select, VDBE-op, and value-size limits apply, and
  a 30-second progress deadline aborts a runaway query as `resource_limit`.
- Only fixed `SELECT` statements over fixed table/column names run. Imported
  configuration never supplies SQL.
- Views and virtual tables cause `unsupported_format` before any adapter query;
  the message reports their counts, not their contents. A schema missing a
  required contract column is rejected with the missing fixed column names.
  A package matching both Chromium and Firefox contracts is refused rather
  than guessed.
- A main database whose header says WAL mode but whose `-wal` was not captured
  is imported as `partial` with a `wal_missing` diagnostic, because committed
  pages may be absent. A `-shm` without `-wal` and any captured `-journal` are
  rejected as inconsistent packages. WAL page-size and magic are validated
  before the copy is opened.
- Corrupt pages, a non-database header, or a failed `PRAGMA quick_check`
  produce `corrupt_evidence`; no run row is written for a package rejected
  before validation completes.

### Time and labels

Chromium stores microseconds since 1601-01-01 UTC; Firefox PRTime stores
microseconds since the Unix epoch. Both normalize exactly and the raw integer,
epoch (`chrome_1601` or `unix`), and unit (`micros`) are stored with the event
time.

- Chromium visits: `visit_time` is the occurrence time. `0` is never treated
  as 1970 or 1601; it stays unresolved with `time_missing`.
- Chromium downloads: `start_time` is the chosen occurrence time when it is
  set; `end_time` is a second named time. If the start sentinel is `0` but the
  end time is valid, the end time is chosen instead of hiding the only observed
  instant. A `0` end time stays unresolved.
- Firefox visits: `visit_date` is the occurrence time; `0` is unresolved.

Chromium referrers are resolved through `from_visit` to the referrer visit's
URL; the transition integer is preserved verbatim. Sync labels come from
`originator_cache_guid` (non-empty → `imported`), otherwise
`is_known_to_sync` (1 → `sync_known`, 0 → `local`, absent/NULL → `unknown`).
Firefox `source` maps 0 → `local`, 1 → `synced`, anything else → `unknown`.

### Raw observations and events

Each logical row is one raw observation with locator kind `logical_row` and
identity `table:<table>:rowid:<id>`; raw fields preserve the original values,
including binary values as `{"binary_hex": "..."}`. A visit becomes
`browser.visit`; a Chromium download becomes `browser.download` with raw
`current_path`, `target_path`, `opened`, state/danger/interrupt values, MIME
metadata, and (when captured) the ordered URL chain from
`downloads_url_chains`. These fields are the inputs to the P5
`process.download_then_execute.v1` rule; the adapter itself does not conclude
that execution followed a download.

A Chromium `downloads` table that lacks known columns, or a package without the
URL-chain table, produces one `download_fields_unavailable` diagnostic naming
the missing fields. Absent fields are omitted from the raw row; they are never
written as invented values. Rows past `--max-records` produce `record_limit`
and a `partial` run.

### Validated schemas

The reference definitions and their fingerprints are listed in
[`tests/fixtures/browser/README.md`](../tests/fixtures/browser/README.md).
Fingerprints describe the exact reference shapes and are recorded per run; no
claim is made that every release of Chromium or Firefox uses one of them.
Unrecognized contracts are rejected with `unsupported_format` and the missing
required column names rather than parsed on a best-effort basis.

## Windows event logs (EVTX)

A captured `.evtx` file is detected by its `ElfFile\0` signature, or declared
with `--format evtx`. It is parsed in the isolated worker (see
[worker-protocol.md](worker-protocol.md)); the mapping below is the same in
both paths. The container and BinXml are decoded by `evtx` 0.13.0;
the adapter preserves the structured `System` and `EventData`/`UserData`
fields. Provider message resources are never loaded, so a missing message table
cannot change an event's meaning. The decoder does not resolve DTDs or external
entities, and the adapter never executes or fetches anything named by a record:
payload strings are stored as text and escaped only when displayed.

### Locators

Each record is one raw observation with locator kind `binary_record` and
identity `evtx-record:<EventRecordID>`. Record IDs are scoped to the captured
object. Exported/selected logs renumber the chunk-local record header from 1, so
that header value is kept only as `chunk_record_id`; the payload
`EventRecordID` is the locator. A record without one falls back to
`evtx-record-ordinal:<n>` and records `evtx_missing_record_id`.

### Time

| Field | Meaning | Handling |
|---|---|---|
| `System/TimeCreated` | logging time | UTC, parsed exactly; raw text preserved; 100 ns FILETIME source ticks stored at microsecond precision |
| Sysmon 1 `UtcTime` | payload occurrence time | no zone marker, read as UTC with that assumption recorded; millisecond precision |

The logging time is the chosen timeline time (the first named time). The
payload time is a second named `occurred` time and never replaces it. An
unreadable `System/TimeCreated` stays `invalid`; the record header timestamp is
preserved in mapped fields but not substituted silently. When the payload has no
`System/TimeCreated` at all, the header timestamp is used as the logging time
and that substitution is recorded as an assumption.

### Tested mappings (version 1)

| Provider | Event | Kind | Mapped fields |
|---|---|---|---|
| `Microsoft-Windows-Security-Auditing` | 4625 | `auth.login_failed` | `user`, `domain`, `service` = `logon_type:<n>`, `logon_type`, `ip`, `workstation`, `auth_package`, `logon_process` |
| `Microsoft-Windows-Security-Auditing` | 4624 | `auth.login_succeeded` | same as 4625 |
| `Microsoft-Windows-Sysmon` | 1 | `process.execute` | `path` (`Image`), `sha256` (from `Hashes`), `user`, `parent_path`, `command_line`, `process_id` |
| `Microsoft-Windows-Security-Auditing` | 4688 | `process.execute` | `path` (`NewProcessName`), `sha256` (from `Hashes`), `creator_user`, `parent_path`, `command_line`, `process_id` |

`service` is the logon type because it is the recorded discriminator that is
always present; the authentication package is kept separately. The 4688 creator
is mapped as `creator_user`, not `user`: the account that created a process is
not the account the process runs as.

Every other provider/event stays `windows.event_log` with `provider`,
`channel`, `event_id`, `record_id`, `chunk_record_id`, `record_ordinal`,
`computer`, and `version`. A mapped field is written only when the record
carries it: a `-` account, an absent digest, or a malformed `Hashes` value stays
absent rather than being guessed. Adding a mapping requires a test next to
these.

### Bounds, corruption, and truncation

- A record larger than `--max-record-bytes` produces `record_too_large` and no
  event.
- `--max-records` produces `record_limit` and a `partial` run.
- A chunk or record the decoder cannot read produces `evtx_parse_error` with the
  chunk or record locator, and the run ends `partial`.
- The header's chunk counter is stale on logs that were not cleanly closed, so
  truncation is judged from the container layout: the chunk area after the 4 KiB
  header must be a whole number of 64 KiB chunks. A trailing partial chunk
  produces `truncated_evidence` and a `partial` run even when the parser returns
  the complete chunks it can read. A file shorter than the header block is
  flagged the same way with no records. A prefix cut exactly on a chunk boundary
  is indistinguishable from a shorter complete log and is not claimed as
  truncation.
- A file without a readable 128-byte EVTX header fails the import (exit `2`) and
  records no run; it is never treated as an empty log.
- Carved records are not enabled (`recover_records` stays off). If a decoder
  ever marks a record as recovered, it is imported with an
  `evtx_recovered_record` diagnostic.

## Entity fields (P5.1)

Entity resolution reads only these recorded field names; it never parses a
message body into an identity. Both JSON objects and journal `[name, value]`
pair arrays are accepted, and only string or integer values are used.

| Entity | Fields (first present wins) |
|---|---|
| user | `user`, `username`, `account`, `user.name` |
| IP | `src_ip`, `remote_ip`, `source_ip`, `ip` |
| process | `pid`, `_PID`, `process_id` (digits only), plus `_BOOT_ID`/`boot_id`/`boot` |
| path | `path`, `current_path`, `target_path` |
| digest | `sha256`, `sha256_hex`, `hash` (exactly 64 hex characters) |
| host | the event's recorded host claim (`host` JSONL mapping, syslog hostname, journal `_HOSTNAME`) |

Capture events use the captured object instead: the exact native path and a
complete SHA-256. Values containing control characters, empty values, and
values over the documented length bounds are not turned into entities. The
scope and rule tables are in `docs/architecture.md`; an IP or basename match is
always a candidate, and equal digests always mean equal bytes only.

## Not supported (deliberate)

- Native `.journal` files (export them first with `journalctl -o export`).
- Inferring RFC 3164 years from file mtimes, rotation names, or arrival order.
- Regular-expression or executable field mappings.
- Reordering or correlating events across hosts or boots.
- Interpreting structured data as fields; it is preserved as raw text.
- Any syslog pattern outside the table above.
- Rollback-journal browser packages, interpreted virtual tables/views, and
  guessing a browser family or missing sidecar from partial evidence.
- Executing or importing browser download contents; only metadata is read.
- Rendering provider messages from Windows message DLLs, resolving XML
  entities/DTDs, or carving deleted records from unallocated EVTX chunk space.

## Rule parameters (P5.2)

`ghosttrace analyze --rules <file.toml>` accepts one bounded TOML document.
Sections and keys are fixed; `deny_unknown_fields` and range checks apply, so a
misspelled key fails instead of falling back to a default.

```toml
[auth.fail_then_success]
failures = 5            # 1..=100
window_seconds = 600    # 1..=86_400

[process.download_then_execute]
window_seconds = 900    # 1..=86_400

[time.clock_discontinuity]
threshold_seconds = 2   # 0..=86_400

[activity.outside_declared_hours]
timezone = "Europe/Berlin"   # IANA zone, required
weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri"]
start = "09:00"              # inclusive
end = "17:00"                # exclusive
holidays = ["2026-12-24"]    # optional, outside the schedule entirely
```

Absent sections use the documented defaults. The schedule has no default:
without `timezone`, `weekdays`, `start`, and `end` the outside-hours rule stays
`not_evaluated`. There are no expressions, patterns, scripts, or per-record
predicates — a parameter changes thresholds and windows, never logic. The
effective configuration digest is recorded with the analysis run, so a finding
can be reproduced from its revision and parameter set.

## Signing keys and detached signatures (P9.1)

Signing uses standard formats only; there is no GhostTrace key container.

**Private key file.** An encrypted PKCS#8 PEM (`-----BEGIN ENCRYPTED PRIVATE
KEY-----`, RFC 5958) with PBES2, scrypt (log₂N 14, r 8, p 1) and AES-256-CBC,
written by `pkcs8` 0.11 with OS randomness. The file is created with mode `0600`
and never overwritten. The loader refuses:

- symlinks, non-regular files, files larger than 64 KiB;
- group/other-readable files and files owned by another user (Unix);
- legacy PBES1 schemes (DES/RC2/MD2/MD5/SHA-1), non-AES-256-CBC ciphers;
- scrypt cost above 2¹⁶, block size above 16, parallelism above 4;
- PBKDF2 above 2,000,000 iterations or a PRF other than HMAC-SHA-256;
- passphrases shorter than 8 bytes or longer than 1024 bytes.

The public key is the 32-byte Ed25519 verifying key, lowercase hex. The key
fingerprint is the SHA-256 of those 32 bytes, lowercase hex. Both are safe to
publish; neither identifies a person.

**Detached signature.** `<manifest>.sig.json`, stable pretty JSON with one
trailing newline:

```json
{
  "format": "ghosttrace-signature/1",
  "algorithm": "ed25519",
  "manifest_sha256": "<64 hex>",
  "public_key": "<64 hex>",
  "key_fingerprint": "<64 hex>",
  "signature": "<128 hex>"
}
```

The signature covers `b"GhostTrace manifest v1"` + `0x00` + the 32-byte SHA-256
of the **complete manifest file**. Signing and verification hash the same bytes,
so whitespace, ordering, entry, or digest changes invalidate the signature.
Verification is strict (`verify_strict`), rejects unknown fields and duplicate
JSON keys, and checks that the fingerprint matches the embedded public key.
The sidecar never embeds the manifest and never contains the private key.

**Trust.** A user-maintained text file outside the case: one lowercase or
uppercase 64-character fingerprint per line, `#` comments and blank lines
ignored, every other line rejected with its line number. Trust is a preference,
not evidence, and it is excluded from portable case backups (P9.2).

## Portable package and backup inventories (P9.2)

Both portable formats use the same strict inventory rules: relative paths with
`/` separators, no `..`, no absolute paths, no backslashes or control
characters, no duplicates, no symlinks, exact byte lengths, and SHA-256 over the
exact bytes. A file present but unlisted is a rejection.

**Package** (`ghosttrace-package/1`, `package.json`):

```json
{
  "format": "ghosttrace-package/1",
  "package_id": "package-acq-…-<unix>",
  "case_id": "…", "case_label": "…", "acquisition_id": "…", "revision": "…",
  "redacted": false, "redaction": null, "signature": "unsigned",
  "files": [{"path": "report.json", "role": "report",
             "sha256": "<64 hex>", "byte_length": 1234}],
  "limitations": ["…"]
}
```

The directory also holds `README.txt`, `report.json`, `report.html`,
`report.csv`, `objects.csv`, `manifest.json`, an optional
`manifest.json.sig.json`, and `objects/<sha256>` (content-addressed, so no
recorded path can escape the directory). With a signing key the inventory is
signed as `package.json.sig.json` using the P9.1 envelope; the signed message is
the same domain separation over the SHA-256 of the complete `package.json`.

**Backup** (`ghosttrace-backup/1`, `backup.json`): the same inventory shape plus
`schema_version` and an `excluded` list, with `case.sqlite` (a consistent online
backup, checkpointed to one file), `case.toml`, `manifests/`, and
`objects/sha256/<bucket>/<hex>`. Backups are unsigned by design; restore verifies
every digest and reference before publishing. Signing keys, trusted-key lists,
generated reports, diagnostics, and staging artifacts are excluded.
