# Command-line interface

The CLI is the alpha entry point for creating a case and capturing a folder.
It shares the core service with the future desktop and TUI front ends; it never
talks to SQLite directly.

```
ghosttrace case create --case <DIR>.ghosttrace-case --label <LABEL>
ghosttrace scan --case <DIR>.ghosttrace-case --source <PATH> [--source <PATH>...]
ghosttrace status --case <DIR>.ghosttrace-case
ghosttrace timeline --case <DIR>.ghosttrace-case [filters]
ghosttrace diff --case <DIR>.ghosttrace-case --before <ID> --after <ID>
ghosttrace import --case <DIR>.ghosttrace-case --path <CAPTURED-PATH> [mapping]
ghosttrace verify --case <DIR>.ghosttrace-case [--manifest <FILE>]
ghosttrace report --case <DIR>.ghosttrace-case --output <DIR> [--report-id NAME]
ghosttrace sqlite-info
```

## Output contract

- **stdout** is machine JSON, one object, no ANSI decoration, pipe-safe.
- **stderr** carries progress, source-method warnings, and JSON errors.
- Native paths are printed in the reversible encoded form (`%FF`, `%u00XX`),
  never as raw bytes and never with terminal control sequences.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Requested operation completed with no material omissions |
| `1` | Operation failed (missing case, storage or permission error) |
| `2` | Invalid usage (bad arguments or case layout) |
| `3` | Partial result: coverage omissions, copy skips, or cancellation |
| `4` | Manifest verification failed (tampering, missing object, malformed or unsupported manifest) |

A `3` is a result, not a crash: the acquisition row and manifest exist, and
`status` shows exactly which paths were omitted and why.

## `case create`

Creates a new private case tree. The directory name must end in
`.ghosttrace-case`; an existing case is never overwritten.

```bash
ghosttrace case create \
  --case /cases/investigation.ghosttrace-case \
  --label "Laptop review" \
  --timezone Europe/Berlin
```

`--timezone` is display-only. It is never applied to source timestamps; those
carry their own semantics and uncertainty (see `docs/timestamps.md`).

## `scan`

Captures one or more roots into an existing case: no-follow traversal, coverage
ledger, streaming SHA-256 copy, atomic publication, manifest v1.

```bash
ghosttrace scan \
  --case /cases/investigation.ghosttrace-case \
  --source /evidence/export \
  --method protected-copy \
  --claimed-source "USB image mounted read-only"
```

Options: `--max-depth` (default 64), `--max-entries` (default 1,000,000),
`--max-file-bytes` (default 16 GiB; larger files are recorded as excluded and
never read), `--method protected-copy|live-best-effort`, `--claimed-source`.

### Choose the source method deliberately

- **protected-copy** (default, recommended): capture from a copy made by a
  write-blocked or equivalent process. GhostTrace verifies the documented
  source claim; it cannot prove how the copy was produced.
- **live-best-effort**: capture a live folder. Files can change or vanish
  during the run; access-time metadata may be affected by reading. The coverage
  ledger records what was seen, but a live scan is not a forensic image.

The warning is printed at the moment you choose, not buried in documentation.

### Progress and cancellation

Progress lines go to stderr (`progress: <bytes> bytes copied, <objects>
objects published`). `Ctrl-C` stops after the current 64 KiB chunk:
unstarted paths become explicit `unobserved` coverage rows, the acquisition
state is `cancelled`, and the exit code is `3`. Nothing half-written is
published; staging is removed.

## `status`

```json
{"case_id":"investigation","display_timezone":"Europe/Berlin",
 "acquisitions":[{"id":"acq-…","method":"protected_copy","state":"completed",
                  "objects":2,"coverage_rows":3}],
 "coverage":{"captured":3},"recoverable_jobs":[],
 "recovery":{"abandoned_staging":0,"orphan_objects":0}}
```

`recoverable_jobs` lists acquisitions interrupted by a crash; they are never
auto-completed. `recovery.orphan_objects` counts published objects without a
database reference (a crash between rename and commit). The CLI reports them;
it never deletes evidence.

## `timeline`

```bash
ghosttrace timeline --case <CASE> [--last 24h] [--until 2026-10-27T12:00:00Z] \
  [--kind file.observed] [--host HOST] [--source capture.metadata.v1] \
  [--unresolved] [--revision RUN_ID] [--limit 200] [--cursor SECONDS:NANOS:EVENT_ID]
```

- `--last` anchors to the **newest chosen instant in the case** (or to
  `--until` when both are given) and subtracts the window. It is never
  "now": a case captured last month still answers `--last 24h` about its own
  last day.
- `--until` is an exclusive RFC 3339 upper bound.
- The resolved view and the unresolved view are separate. Events with no
  resolved time never appear in the ordered timeline; `--unresolved` lists
  them explicitly.
- `--kind`, `--host`, and `--source` (`parse_runs.parser_id`) are exact
  filters.
- Paging is keyset-based: pass `next_cursor` back as `--cursor`. Repeating a
  query returns the identical page; no skips, no duplicates.
- `--revision` reads one parse run. Each import creates its own revision, so
  re-importing with different assumptions does not overwrite the earlier one.
  Default: the newest revision of the latest acquisition. The literal `r1`
  remains valid and is what capture-only cases use.

```json
{"revision":"r1","resolved_view":true,"after_seconds":1792999200,
 "before_seconds":null,"anchor_seconds":1793085600,
 "rows":[{"event_id":"evt-…","kind":"file.observed","chosen_seconds":1793085186,
          "chosen_nanos":0,"time_status":"resolved","host_claim":null}],
 "next_cursor":null}
```

## `search`

```bash
ghosttrace search --case <CASE> --text 'sshd -root "accepted password"' \
  [--kind auth.login_succeeded] [--host HOST] [--source parser] \
  [--after SECONDS] [--before SECONDS] [--unresolved] \
  [--revision RUN_ID] [--limit 200] [--cursor SECONDS:NANOS:EVENT_ID]
```

Full-text search over **indexed** event summary, kind, and host text. Raw
field values and evidence bytes are not indexed; use `timeline` and event
detail to reach them.

The grammar is deliberately tiny, and anything outside it is **rejected with
an explanation** rather than reinterpreted:

| Accepted | Meaning |
| --- | --- |
| `sshd accepted` | both terms must occur (implicit AND) |
| `"accepted password"` | an adjacent phrase |
| `-root` | exclude a term (never the only term) |
| `-` inside a word | literal, e.g. `host-a` |
| `""` doubled inside a phrase | a literal quote |

| Rejected | Why |
| --- | --- |
| `col:term`, `prefix*`, `a AND b`, `NEAR` | FTS5 operators and column syntax |
| `"unterminated`, empty input, > 4 KiB | incomplete, empty, or oversized |

The validated expression is passed to FTS5 as a bound parameter; operator
text never becomes SQL. Filters, ordering, and keyset paging are identical to
`timeline`, including the separate `--unresolved` view.

```json
{"text":"accepted password","revision":"pr-…","resolved_view":true,
 "rows":[{"event_id":"ev-…","kind":"auth.login_succeeded","summary":"sshd accepted password for bob from 10.0.0.6",
          "host_claim":"host","chosen_seconds":1793091600,"chosen_nanos":0,"time_status":"resolved"}],
 "next_cursor":null}
```

## `diff`

```bash
ghosttrace diff --case <CASE> --before <ACQ> --after <ACQ> [--limit 200] [--cursor PATH]
```

Compares two acquisitions of the same roots by recorded full hash, size, and
source mtime. Classes:

| Class | Meaning |
|---|---|
| `unchanged` | Same full hash and same recorded size/mtime |
| `metadata_changed` | Same full hash, different recorded metadata |
| `content_changed_equal_metadata` | Different hash while size **and** mtime match |
| `content_changed` | Different hash and different metadata |
| `appeared` | Present only in the later captured scope |
| `not_present_in_captured_scope` | Present in the earlier capture, absent later — **not** "deleted" |
| `move_candidate` | Same full hash at a different path; bytes do not prove a copy or move |
| `unknown` | Scope mismatch, coverage gap, or missing digest |

Scope comes first:

- Acquisitions whose **root sets differ** are not compared. Every row is
  `unknown` with a warning; nothing is reported as appeared or absent.
- If the later acquisition has a coverage gap at a path (permission denied,
  unstable, oversized, cancelled, …), absence there is `unknown`, not
  `not_present_in_captured_scope`.
- Equal bytes across paths are a **candidate** relation only. GhostTrace does
  not infer that an operator copied, moved, or hardlinked anything.
- Timestamp equality never proves unchanged bytes, and unchanged bytes never
  prove an untouched file: `content_changed_equal_metadata` exists precisely
  because mtimes can be preserved deliberately.

The response is `{"before_acquisition","after_acquisition","summary","rows",
"next_cursor"}`; `summary` counts every class plus `same_content_relations`
(paths sharing one full hash inside a snapshot) and `scope_compatible`.

## Reading the scan result

```json
{"acquisition_id":"acq-…","state":"completed","objects":2,"bytes":12,
 "coverage":{"captured":3,"excluded":0,"inaccessible":0,"unstable":0,
             "vanished":0,"unsupported":0,"unobserved":0,"hardlink_aliases":0},
 "gaps":[],"manifest":"manifest-acq-….json"}
```

`gaps` contains bounded examples (3 per category, 32 total); the complete list
is in the case's `coverage` table. Every gap carries a stable `code`
(`policy_excluded`, `permission_denied`, `symlink_not_followed`,
`special_file`, `open_failed`, `metadata_changed`, `vanished`,
`traversal_limited`, `deduplicated_hardlink`) so scripts never parse prose.

Verify stored copies independently with any SHA-256 tool: the manifest lists
each object's byte length and digest, and the object path is its digest.

## `verify`

Re-reads one acquisition manifest, re-hashes every stored object, and checks the
detached signature when one is present or named. The three statuses are
reported separately: object digests, signature validity, and key trust.

```bash
ghosttrace verify --case <DIR>.ghosttrace-case
ghosttrace verify --case … --acquisition <ID>
ghosttrace verify --case … --manifest <FILE>
ghosttrace verify --case … --signature <FILE> --trust <FILE>
```

Without `--signature`, the sidecar `<manifest>.sig.json` is used when it
exists; naming a missing sidecar is an error, never "absent". `--trust` is a
user-maintained text file with one 64-character key fingerprint per line
(`#` comments and blank lines allowed). Trust lives outside the case and is
never written into it.

Success prints one JSON line:

```json
{"verified":true,"manifest_id":"manifest-acq-…","acquisition_id":"acq-…",
 "format":"ghosttrace-manifest/1","objects_verified":3,"total_bytes":22,
 "captured":3,"gaps":0,"signed":true,"signature":"valid",
 "key_trust":"untrusted","key_fingerprint":"…","public_key":"…",
 "capture_complete":true,"explanation":"…"}
```

`signature` is `absent`, `valid`, or `invalid`; `key_trust` is
`not_applicable`, `untrusted`, or `trusted`. A **valid signature from an unknown
key is not a failure**: it proves the bytes were signed by that key, not that
the key is yours. `explanation` states the same thing in one sentence, including
whether coverage gaps were recorded.

Exit codes: `0` accepted, `4` the manifest did not verify or the signature does
not cover these bytes, `1` the file or case could not be read, `2` invalid
usage.

Verification fails closed on:

| Condition | Machine code |
| --- | --- |
| any stored object's bytes differ from its digest | `integrity_mismatch` |
| a referenced object is missing from the store | `corrupt_evidence` |
| malformed JSON, duplicate JSON keys, unknown format version | `unsupported_format` |
| duplicate object IDs or store paths | `unsupported_format` |
| a `store_subpath` outside `objects/sha256/<bucket>/<hex>` | `unsupported_format` |
| a signature that does not cover the exact manifest bytes | `integrity_mismatch` |
| unsupported signature format/algorithm, malformed hex, fingerprint mismatch | `unsupported_format` |

Recorded coverage gaps (`gaps > 0`) do **not** fail verification: they are part
of the honest record, not tampering. A cancelled acquisition writes no manifest;
verifying it reports a missing file. A signature proves the bytes were signed by
a key. It cannot prove when collection occurred, that the host was truthful, or
that custody was legally sufficient.

## `sign`

Signs the exact bytes of a stored manifest with an encrypted Ed25519 key. The
passphrase is read from the terminal, never from an argument or the environment.

```bash
ghosttrace sign --manifest <CASE>/manifests/manifest-acq-….json --key ~/keys/signing.pem
ghosttrace sign --manifest … --key … --out /elsewhere/manifest.sig.json
```

The default sidecar is `<manifest>.sig.json`; an existing sidecar is never
overwritten. The signed message is the ASCII domain `GhostTrace manifest v1`,
one NUL byte, then the SHA-256 of the complete manifest file. Any whitespace,
entry, or digest change therefore invalidates the old signature. The sidecar
records the format, algorithm, manifest digest, public key, key fingerprint, and
signature — never the manifest or the private key.

## `key`

```bash
ghosttrace key generate --out ~/keys/signing.pem
ghosttrace key import --in old.pem --out ~/keys/signing.pem
ghosttrace key public --key ~/keys/signing.pem
```

`generate` prompts twice for a new passphrase (at least 8 bytes) and writes a
standard encrypted PKCS#8 PEM (PBES2 with scrypt, AES-256-CBC) created with mode
`0600`. An existing file is never overwritten and a key may not be written
inside a case directory. `import` decrypts an existing encrypted PKCS#8 key and
re-encrypts it under a new passphrase. `public` prints the public key and
fingerprint; the private key never leaves memory unencrypted.

The loader refuses symlinks, group/other-readable files, files owned by another
user, oversized key files, legacy PBES1 schemes, non-AES-256-CBC ciphers, and
KDF parameters above the accepted bounds. Zeroization covers the in-memory key
and passphrase buffers; it cannot protect against swap, crash dumps, or a
compromised host. Passphrase prompts require a terminal: piping stdin is
refused before any key is created or read.

## `report`

Builds a versioned report from recorded rows only and publishes it atomically:

```bash
ghosttrace report --case <DIR>.ghosttrace-case --output /cases/reports \
  [--acquisition <ID>] [--revision RUN_ID] [--limit 500] [--report-id NAME] \
  [--csv] [--redact <CATEGORY>]...
```

Output: `{"report_id","format","directory","json","html","objects","events","gaps","csv","redacted","redaction"}`.

`--redact` categories: `case-label`, `source-paths`, `object-paths`,
`timeline-summaries`, `timeline-hosts`. Each selected value is replaced with
`[redacted]` in the published copy; the case, the database, and the stored
evidence are never changed. A `redaction.json` ledger is written beside the
report and records only field names and counts — never the removed text.
`--csv` adds `report.csv`, a spreadsheet-safe timeline projection.
The directory holds `report.json` (full fidelity, `ghosttrace-report/1`) and
`report.html` (self-contained, no scripts/links/remote resources, all values
escaped, control/bidi characters rendered visibly).

An existing report directory is never overwritten: the command exits `1` and
leaves the previous export untouched. A failure during publication removes the
staging directory, so no partial export appears complete. See
[reports.md](reports.md).

The timeline is pinned to **one revision**: `--revision` names it, and by
default it is the newest parse run of the acquisition. Because a re-import
records another revision instead of replacing the earlier one, pinning makes
the report reproducible — building the same selection again yields the same
timeline. The pinned run id appears in `report.json` (`revision`) and in the
HTML provenance line.

## `package`

Builds a directory a second person can verify offline: the acquisition
manifest, the stored objects the report cites, the report (JSON, HTML, CSV),
a verifier `README.txt`, and a SHA-256 inventory over every file.

```bash
ghosttrace package --case <DIR>.ghosttrace-case --output /cases/packages \
  [--acquisition <ID>] [--revision RUN_ID] [--limit 500] \
  [--manifest FILE] [--signature FILE] [--redact <CATEGORY>]... [--key KEY.pem]
```

With `--key`, `package.json` is signed with the same detached Ed25519 envelope
as a manifest (`package.json.sig.json`); without it the package is honestly
unsigned. Output: `{"package_id","directory","inventory","files","total_bytes",
"signed","public_key","key_fingerprint","redacted","redaction"}`. An existing
package directory is never overwritten.

## `verify-package`

```bash
ghosttrace verify-package --package <DIR> [--trust ~/trusted-keys.txt]
```

Verifies every listed file's exact length and SHA-256, rejects missing,
modified, unlisted, duplicate, or escaping paths, and checks the inventory
signature when present. Exit `0` accepted, `4` the package did not verify,
`1` the inventory or directory could not be read, `2` invalid usage. A valid
signature from a key that is not in the trust file is reported as
`"signature":"valid","key_trust":"untrusted"` and is still accepted.

## `backup`

```bash
ghosttrace backup --case <DIR>.ghosttrace-case --output /cases/backups
```

Takes a consistent online SQLite backup (committed WAL data included) plus every
referenced immutable object, `case.toml`, and the manifests, with a `backup.json`
inventory over all of it. Signing keys and trusted-key lists are excluded on
purpose. Output: `{"backup_id","directory","inventory","case_id",
"schema_version","files","total_bytes"}`. Publication is atomic; an existing
backup is never overwritten.

## `restore`

```bash
ghosttrace restore --backup <BACKUP_DIR> --destination <NEW>.ghosttrace-case
```

Verifies the inventory, copies into a private sibling staging directory,
re-verifies every file, checks `PRAGMA integrity_check`, the schema version, the
case id, and every object reference, and only then renames the new case into
place. The destination must not exist. Object paths in the case are relative, so
a relocated case opens with its native paths and provenance intact. Exit `0`
restored, `4` the backup is missing or corrupt, `1` a storage failure, `2`
invalid usage.

## Packaging an early build

```bash
cargo build -p ghosttrace-cli --release
cargo run -p xtask -- package --output dist --version 1.0.0-rc.2
```

The archive includes the binary, licences, docs, `help.txt`, sample data, and a
`build-info.json` inventory, plus a sibling `.sha256`. Existing archives are
never overwritten.

## `import`

Parses one **captured** object through a bounded, versioned adapter. The object
is re-hashed against its recorded digest before parsing; a mismatch exits `1`
and no run is recorded.

```bash
ghosttrace import --case <DIR>.ghosttrace-case --path logs/app.jsonl \
  [--time-field ts] [--time-format rfc3339] [--message-field msg] \
  [--host-field host] [--kind-field kind] [--default-kind log.record]

ghosttrace import --case <DIR>.ghosttrace-case --path var/log/syslog \
  --format syslog-3164 --timezone Europe/Berlin --year 2026

ghosttrace import --case <DIR>.ghosttrace-case \
  --path "Profile 1/History"
```

`--path` is the captured relative path; `--object <ID>` selects the evidence
object directly. Exactly one is required. `--acquisition` selects a capture
(default: latest). `--format` accepts `jsonl`, `syslog-5424`, `syslog-3164`,
`journal-export`, `browser`, or `evtx` and overrides signature detection; both
detected and declared formats are reported. Native `.journal` files are not
parsed: capture a `journalctl -o export` stream first.

Risky adapters (EVTX and journal export) run in an isolated parser worker: this
executable in a private mode, resolved explicitly and never through `PATH`. The
worker gets a private copy of the object and returns bounded, validated frames;
a crash, hang, or malformed output ends the run `failed`, never `completed`.
`--worker <PATH>` names another worker binary; `--no-worker` runs the adapter
in-process for debugging and gives up the isolation. The contract and its
limits are in [worker-protocol.md](worker-protocol.md).

For browser history, `--path` names the captured main SQLite database; captured
`<path>-wal` and `<path>-shm` sidecars in the same acquisition are found
automatically. The schema chooses `browser.chromium` or `browser.firefox`.
There are no per-table switches: the adapter validates the contract and
rejects unsupported or inconsistent packages rather than guessing. A package
in WAL mode without its WAL imports as `partial` with `wal_missing`; a `-shm`
without `-wal` or any `-journal` sidecar is rejected with exit `2`. View,
virtual-table, corrupt-page, and missing-column failures also exit `2` as
`unsupported_format`/`corrupt_evidence` and record no run.

A captured Windows event log (`.evtx`) is detected by its `ElfFile\0`
signature or declared with `--format evtx`. It has no mapping flags: the
adapter's fixed, tested provider mappings are listed in
[formats.md](formats.md#windows-event-logs-evtx). Unreadable chunks and
truncated chunk areas are reported and end the run `partial`.

Output: `{"run_id","acquisition_id","evidence_id","path","parser_id",
"parser_version","detected_format","declared_format","state","records",
"observations","events","diagnostics","diagnostics_total",
"diagnostics_truncated"}`.

Exit codes: `0` every record parsed cleanly, `3` diagnostics were recorded or
the run was cancelled, `2` invalid configuration/signature (no run recorded),
`1` import failed (including digest mismatch). Re-running the same object with
the same configuration reuses the run id and adds no duplicate rows.

Time rules and the exact accepted/rejected records are in
[formats.md](formats.md). Unmatched messages stay raw observations; RFC 3164
times stay unresolved without `--year`/`--timezone`; DST overlaps and
December→January sequences stay `ambiguous`. Journal monotonic values stay
boot-scoped and never choose a timeline position; only
`__REALTIME_TIMESTAMP` does. Browser times keep their Chromium-1601 or Firefox
PRTime epoch and unit next to the normalized instant; download fields that the
captured schema does not contain are reported, never invented.

## `analyze`

Evaluates the five compiled rules over one revision and prints the run.

```bash
ghosttrace analyze --case <DIR>.ghosttrace-case \
  [--revision <RUN_ID>] [--rules rules.toml]
```

`--revision` defaults to the newest revision of the latest acquisition. Without
`--rules`, documented defaults are used and the outside-hours rule stays
disabled. Unknown TOML keys and out-of-range values exit `2` with
`invalid_request`; a case with no parse run also exits `2`.

Output: `{"run_id","revision","rules_id","rules_version","config_digest",
"state","outcomes":[...],"findings":[...]}`. Each outcome carries
`rule_id`, `rule_version`, `status` (`evaluated` or `not_evaluated`), `reason`,
`findings`, `events_considered`, `excluded`, and `truncated`. Each finding
carries the rule id/version, sorted supporting `event_ids`, the exact
`predicates`, `severity`, `rationale`, `alternatives`, and the current
`disposition`.

Exit codes: `0` the pass completed, `3` a bound truncated a rule, `2` invalid
parameters or no revision, `1` storage failure. The same revision and parameter
set produce the same `run_id` and finding ids, and a stored analyst disposition
is reported again after a re-run. There is no maliciousness score in any field.

## `annotate`

Records or reads an analyst annotation: a note, a tag set, or a finding
disposition. Annotations are append-only revisions over the same targets the
desktop reviews; they never edit a recorded observation.

```bash
ghosttrace annotate --case <DIR>.ghosttrace-case record \
  (--event <EVENT_ID> | --finding <FINDING_ID>) \
  --author <LABEL> [--text <NOTE>] [--tags a,b] [--disposition confirmed]

ghosttrace annotate --case <DIR>.ghosttrace-case history \
  (--event <EVENT_ID> | --finding <FINDING_ID>) [--limit 50]
```

Exactly one of `--event` or `--finding` is required; naming both (or neither)
exits `2`. A `--disposition` applies to a finding and is rejected on an event.
A bookmark is the recorded `bookmark` tag on an event.

Output of `record`:
`{"target_id","revision_id","previous_revision","author_label","disposition",
"tags"}`. Output of `history`: `{"target_id","revisions":[...]}` with the newest
revision first; each revision carries `revision_id`, `previous_revision`,
`author_label`, `created_seconds`, `text`, `tags`, and `disposition`.

Exit codes: `0` the revision was appended (or the history was read), `2`
invalid arguments, target, or author label, `1` a rejected append — including a
`conflict` when the newest revision moved since this append was derived, which
is reported instead of overwriting someone else's edit.

## `tui`

Browses one case interactively. The TUI reads through the same contracts as
`timeline`, `search`, and `analyze`, so a selection yields the same recorded
event and detail the desktop inspector shows.

```bash
ghosttrace tui --case <DIR>.ghosttrace-case [--revision <RUN_ID>]
```

Views: the paginated timeline, event detail (observations with locators, times
with assumptions, entities, run diagnostics), findings with their rationale,
alternatives, predicates, and supporting events, a status/progress line, and
the key help. The essential keys are always shown in the footer; `?` opens the
full list.

| Key | Action |
|---|---|
| `j`/`k`, `Up`/`Down` | move the selection |
| `PgUp`/`PgDn`, `J`/`K` | move ten rows |
| `g`/`G`, `Home`/`End` | first or last row |
| `n` / `p` | next or previous page |
| `/` | search with the same grammar as `ghosttrace search` |
| `f` | exact filters: `kind= host= source= after= before=` |
| `u` | unresolved-time view |
| `a` | analyze the active revision with the five compiled rules |
| `Tab` | switch timeline and findings |
| `?` | help |
| `q`, `Ctrl+C` | quit |

Filter values are exact and cannot contain spaces; `after`/`before` take
RFC 3339 instants and must be given in order. Unknown or repeated keys, empty
values, and bad instants are errors in the status line, never silently ignored.
A revision is resolved once at start (the newest parse run unless `--revision`
is given); a case with no parse run opens with an explicit empty state.

Safety:

- Evidence text is escaped with `ghosttrace_core::text::escape_for_display`
  before it reaches the terminal, so OSC/CSI/control bytes in a log are shown
  as text. Table cells also flatten newlines so a record cannot fabricate rows.
- Raw mode and the alternate screen are entered behind a restoration guard;
  normal exit, an early quit, an error return, and an unwinding panic all
  restore the cursor, screen, and mode.
- The TUI needs a terminal on stdin and stdout. Redirected output exits `2`
  with a message and writes no ANSI bytes, so pipelines must use `timeline`,
  `search`, `analyze`, or the JSON commands.

Exit codes: `0` normal exit, `1` the case could not be opened or the terminal
failed, `2` stdin/stdout is not a terminal or the arguments are invalid.

The TUI does not capture, import, export, or annotate: those stay explicit CLI
or desktop actions. Mouse input is not required for any view.

## `completions`

```bash
ghosttrace completions bash > ghosttrace.bash
ghosttrace completions zsh  > _ghosttrace
ghosttrace completions fish > ghosttrace.fish
```

The script is written to stdout; this is the only command whose stdout is not
JSON. It opens no case and writes no files. The release archive ships generated
scripts under `completions/`; they describe the same command surface as the
packaged binary.

## Synthetic samples

Two tracked, reproducible investigations exercise the commands above without
real evidence:

- [`samples/failed-logon-timeline/`](../samples/failed-logon-timeline/README.md)
  — JSONL import, exact timeline/search filters, two rule findings, honest
  `not_evaluated` outcomes, report export, verification.
- [`samples/misleading-snapshots/`](../samples/misleading-snapshots/README.md)
  — two captures of one folder, equal-metadata content change, move candidates,
  and a coverage gap that stays `unknown`.

Both build a scratch case under `/tmp` and reference only tracked synthetic
data. If a command in this guide fails, see
[troubleshooting.md](troubleshooting.md) before opening an issue.
