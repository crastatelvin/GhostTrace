# Ten-minute synthetic folder investigation

This walkthrough exercises the full alpha loop on a folder you create yourself:
capture, second capture, coverage-aware diff, manifest verification, and report
export. It takes about ten minutes and every expected value below is exact.

Nothing here touches real evidence. Work in `/tmp` or another scratch directory.

## 0. Build (2 minutes)

```bash
cargo build -p ghosttrace-cli
export PATH="$PWD/target/debug:$PATH"
```

## 1. Create the scene (1 minute)

```bash
export WORK=/tmp/gt-walkthrough
rm -rf "$WORK" && mkdir -p "$WORK/evidence/notes"
cd "$WORK"
printf 'alpha\n'   > evidence/notes/a.txt
printf 'bravo\n'   > evidence/notes/b.txt
printf 'charlie\n' > evidence/other.txt
sha256sum evidence/notes/a.txt evidence/notes/b.txt evidence/other.txt
```

Expected:

```
b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060  evidence/notes/a.txt
5da8f23decf397b13f4f55b6fb8a61936238bfe08ed9d901132974f1beccc45c  evidence/notes/b.txt
999d1d048ee9123272dd9b718680551c83e867935b47c2650e6906dc22674e47  evidence/other.txt
```

## 2. Case and first capture (1 minute)

```bash
ghosttrace case create --case "$WORK/case.ghosttrace-case" --label walkthrough
export FIRST=$(ghosttrace scan --case "$WORK/case.ghosttrace-case" \
  --source "$WORK/evidence" --claimed-source "demo folder" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["acquisition_id"])')
```

Expected create output: `case_id:"case"`, `display_timezone:"UTC"`.

Expected scan output (IDs and times differ):

```json
{"acquisition_id":"acq-…","state":"completed","objects":3,"bytes":20,
 "coverage":{"captured":3,"excluded":0,"inaccessible":0,"unstable":0,
             "vanished":0,"unsupported":0,"unobserved":0,"hardlink_aliases":0},
 "gaps":[],"manifest":"manifest-acq-….json"}
```

Save the acquisition ID in `FIRST` as shown; the next scan is captured in
`SECOND` the same way.

## 3. Change the scene (1 minute)

```bash
printf 'bravo-two\n' > evidence/notes/b.txt
rm evidence/other.txt
printf 'delta\n'     > evidence/notes/c.txt
sha256sum evidence/notes/*.txt
```

Expected:

```
b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060  evidence/notes/a.txt
9a87d2265012186534d95a5160ffbce1e2e2821c04e9281f7b3bb5b93a7df531  evidence/notes/b.txt
673953e0ad7fc53247f4feadc2c2d4506396840d1f8796526f48d47333ac7652  evidence/notes/c.txt
```

## 4. Second capture (1 minute)

```bash
export SECOND=$(ghosttrace scan --case "$WORK/case.ghosttrace-case" \
  --source "$WORK/evidence" --claimed-source "demo folder" 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["acquisition_id"])')
```

Expected: `objects:3`, `bytes:22`, `captured:3`, `gaps:[]`, exit `0`.

## 5. Diff (2 minutes)

```bash
ghosttrace diff --case case.ghosttrace-case --before "$FIRST" --after "$SECOND"
```

Expected rows (order is by path):

| Path | Class | Reason |
| --- | --- | --- |
| `notes/a.txt` | `unchanged` | same full hash and metadata |
| `notes/b.txt` | `content_changed` | different full hash and metadata |
| `notes/c.txt` | `appeared` | present only in the later captured scope |
| `other.txt` | `not_present_in_captured_scope` | not present in the later captured scope; deletion not established |

Expected summary: `unchanged:1`, `content_changed:1`, `appeared:1`,
`not_present_in_captured_scope:1`, everything else `0`,
`scope_compatible:true`.

`notes/b.txt` is `content_changed` because rewriting it advanced its mtime. If
an operator preserves mtime while changing bytes, the class becomes
`content_changed_equal_metadata` — which is exactly why timestamp equality is
never treated as proof.

`other.txt` is **not** reported as deleted. Its absence from the second
capture's scope is an observation, not a deletion.

## 6. Verify (1 minute)

```bash
ghosttrace verify --case case.ghosttrace-case
```

Expected:

```json
{"verified":true,"manifest_id":"manifest-…","acquisition_id":"…",
 "format":"ghosttrace-manifest/1","objects_verified":3,"total_bytes":22,
 "captured":3,"gaps":0,"signed":false}
```

Now prove the check is real:

```bash
python3 - <<'PY'
import pathlib
objects = pathlib.Path('case.ghosttrace-case/objects/sha256')
object_file = next(path for path in objects.rglob('*') if path.is_file())
data = bytearray(object_file.read_bytes())
data[0] ^= 0xff
object_file.write_bytes(data)
print(object_file)
PY
ghosttrace verify --case case.ghosttrace-case; echo "exit=$?"
```

Expected: exit `4`, stderr `{"error":"integrity_mismatch","message":"integrity_mismatch"}`.
(Repair by re-running the walkthrough in a fresh directory; the case is now
honestly recorded as failing verification.)

## 7. Report (2 minutes)

```bash
ghosttrace report --case case.ghosttrace-case --output out --report-id walkthrough
```

Expected:

```json
{"report_id":"walkthrough","format":"ghosttrace-report/1",
 "directory":"out/walkthrough","json":"out/walkthrough/report.json",
 "html":"out/walkthrough/report.html","objects":3,"events":3,"gaps":0}
```

Open `out/walkthrough/report.html` in a browser. Expected content:

- format `ghosttrace-report/1`, the case label, `UTC`, and the acquisition ID;
- coverage `captured 3`, every gap status `0`;
- three objects with the exact hashes from step 3 (the second capture), plus
  `a.txt`'s unchanged hash;
- three application-clock events, all `resolved`;
- provenance with `signed: no`, and the four fixed limitations.

Confirm the JSON matches:

```bash
python3 - <<'PY'
import json
report = json.load(open('out/walkthrough/report.json'))
assert report['format'] == 'ghosttrace-report/1'
assert report['case']['display_timezone'] == 'UTC'
assert report['coverage']['captured'] == 3
assert report['coverage']['excluded'] == 0
assert {o['sha256'] for o in report['objects']} == {
  'b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060',
  '9a87d2265012186534d95a5160ffbce1e2e2821c04e9281f7b3bb5b93a7df531',
  '673953e0ad7fc53247f4feadc2c2d4506396840d1f8796526f48d47333ac7652',
}
assert report['provenance']['signed'] is False
print('report matches')
PY
```

Finally, confirm the export is append-only:

```bash
ghosttrace report --case case.ghosttrace-case --output out --report-id walkthrough
echo "exit=$?"
```

Expected: exit `1`, `refusing to overwrite`, and `out/walkthrough/report.html`
unchanged.

## What this walkthrough does and does not show

Shows: read-only capture, content-addressed storage, per-path coverage,
independent re-hashing, coverage-aware classification, and a report that carries
its own provenance, limits, and uncertainty.

Does not show: deletion (only absence from scope), attribution, intent, a
signature, or anything from a live source that was not captured. A manifest
verifies bytes; it does not identify who produced them.
