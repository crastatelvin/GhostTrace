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
  [--unresolved] [--revision r1] [--limit 200] [--cursor SECONDS:NANOS:EVENT_ID]
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

```json
{"revision":"r1","resolved_view":true,"after_seconds":1792999200,
 "before_seconds":null,"anchor_seconds":1793085600,
 "rows":[{"event_id":"evt-…","kind":"file.observed","chosen_seconds":1793085186,
          "chosen_nanos":0,"time_status":"resolved","host_claim":null}],
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

Re-reads one acquisition manifest and re-hashes every stored object. Unsigned
integrity check only: it proves the stored bytes still match the record.

```bash
ghosttrace verify --case <DIR>.ghosttrace-case
ghosttrace verify --case … --acquisition <ID>
ghosttrace verify --case … --manifest <FILE>
```

Success prints `{"verified":true,…}` and exits `0`. Any of tampered bytes
(`integrity_mismatch`), a missing object (`corrupt_evidence`), duplicate JSON
keys, an unsupported format version, duplicate object references, or a store
path escaping `objects/sha256/` exits `4`. Recorded coverage gaps do not fail
verification. See [reports.md](reports.md) for the full rule table.

## `report`

Builds a versioned report from recorded rows only and publishes it atomically:

```bash
ghosttrace report --case <DIR>.ghosttrace-case --output /cases/reports \
  [--acquisition <ID>] [--limit 500] [--report-id NAME]
```

Output: `{"report_id","format","directory","json","html","objects","events","gaps"}`.
The directory holds `report.json` (full fidelity, `ghosttrace-report/1`) and
`report.html` (self-contained, no scripts/links/remote resources, all values
escaped, control/bidi characters rendered visibly).

An existing report directory is never overwritten: the command exits `1` and
leaves the previous export untouched. A failure during publication removes the
staging directory, so no partial export appears complete. See
[reports.md](reports.md).

## Packaging an early build

```bash
cargo build -p ghosttrace-cli --release
cargo run -p xtask -- package --output dist --version 0.1.0-alpha.1
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
```

`--path` is the captured relative path; `--object <ID>` selects the evidence
object directly. Exactly one is required. `--acquisition` selects a capture
(default: latest). `--format` accepts `jsonl`, `syslog-5424`, `syslog-3164`, or
`journal-export` and overrides signature detection; both detected and declared
formats are reported. Native `.journal` files are not parsed: capture a
`journalctl -o export` stream first.

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
`__REALTIME_TIMESTAMP` does.
