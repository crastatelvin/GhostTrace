# Synthetic sample: misleading metadata and incomplete coverage

Two captures of the same synthetic folder, built from tracked fixture files.
The point is what the diff refuses to claim:

- a file whose bytes changed while its size and mtime stayed identical;
- a file whose bytes did not change but whose mtime did;
- the same bytes at a new path, reported as a move *candidate* only;
- a path that the later capture could not read, reported as `unknown`, not
  "not present" and not "deleted".

The fixture and scripts are synthetic. No real evidence is involved.

## Files

| Path | Purpose |
|---|---|
| `fixture/alpha.txt` | unchanged bytes |
| `fixture/beta-v1.txt`, `fixture/beta-v2.txt` | equal byte length, different bytes |
| `fixture/gamma.txt` | bytes that move to a new path |
| `fixture/secret.txt` | baseline for a later permission-denied path |
| `fixture/delta.txt` | a path that appears later |
| `setup.sh` | builds the first snapshot with one shared mtime |
| `mutate.sh` | builds the second snapshot |

The scripts copy tracked content into a scratch directory and set mtimes
explicitly; Git does not preserve mtimes, so the scene is materialized instead
of committed with timestamps.

## Run it

From the repository root:

```bash
cargo build -p ghosttrace-cli --release
export PATH="$PWD/target/release:$PATH"

export WORK=/tmp/gt-misleading-snapshots
./samples/misleading-snapshots/setup.sh "$WORK"

ghosttrace case create --case "$WORK/case.ghosttrace-case" --label misleading-snapshots
export FIRST=$(ghosttrace scan --case "$WORK/case.ghosttrace-case" \
  --source "$WORK/evidence" --claimed-source "synthetic snapshot" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["acquisition_id"])')
```

The first scan is complete: 4 objects, 4 captured, 0 gaps, exit `0`.

```bash
./samples/misleading-snapshots/mutate.sh "$WORK"

export SECOND=$(ghosttrace scan --case "$WORK/case.ghosttrace-case" \
  --source "$WORK/evidence" --claimed-source "synthetic snapshot" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["acquisition_id"])')
```

The second scan is partial: 4 objects, 4 captured, **1 gap**
(`secret.txt`, `open_failed`), exit `3`. The assignment still captures the
printed JSON; a partial scan is not a failure to hide. The gap is recorded in
the coverage table and the manifest.

```bash
ghosttrace diff --case "$WORK/case.ghosttrace-case" --before "$FIRST" --after "$SECOND"
ghosttrace verify --case "$WORK/case.ghosttrace-case" --acquisition "$SECOND"
```

## Expected diff

Summary: `unchanged:0`, `metadata_changed:1`,
`content_changed_equal_metadata:1`, `content_changed:0`, `appeared:1`,
`not_present_in_captured_scope:0`, `move_candidates:2`, `unknown:1`,
`scope_compatible:true`.

| Path | Class | Why |
|---|---|---|
| `alpha.txt` | `metadata_changed` | same full hash, different recorded mtime |
| `beta.txt` | `content_changed_equal_metadata` | different full hash while size **and** mtime match |
| `delta.txt` | `appeared` | present only in the later captured scope |
| `gamma.txt` | `move_candidate` | same full hash appears at a new path |
| `gamma-renamed.txt` | `move_candidate` | the other side of the same candidate pair |
| `secret.txt` | `unknown` | coverage gap in the later acquisition; absence is not established |

Two lessons the output makes concrete:

1. **Equal metadata is not equal bytes.** `beta.txt` keeps its size and mtime
   and still changes content. Timestamp equality never proves an untouched
   file.
2. **A gap is not a deletion.** `secret.txt` existed in the first capture and
   could not be read in the second. The diff says `unknown`; it does not say
   the file was removed. A move is likewise only a candidate: equal bytes do
   not prove who moved them or why.

`verify` accepts the partial acquisition (`verified:true`, 4 objects verified,
`gaps:1`, `capture_complete:false`, exit `0`). Coverage gaps are part of the
honest record, not tampering; a cancelled acquisition writes no manifest at
all.

## Clean up

```bash
chmod 600 /tmp/gt-misleading-snapshots/evidence/secret.txt 2>/dev/null || true
rm -rf /tmp/gt-misleading-snapshots
```
