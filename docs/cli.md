# Command-line interface

The CLI is the alpha entry point for creating a case and capturing a folder.
It shares the core service with the future desktop and TUI front ends; it never
talks to SQLite directly.

```
ghosttrace case create --case <DIR>.ghosttrace-case --label <LABEL>
ghosttrace scan --case <DIR>.ghosttrace-case --source <PATH> [--source <PATH>...]
ghosttrace status --case <DIR>.ghosttrace-case
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
| `4` | Verification mismatch (reserved for verify commands) |

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
