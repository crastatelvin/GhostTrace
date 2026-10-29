# Synthetic sample: failed logons, a success, and process/file activity

A tracked JSONL log for exercising import, timeline, search, rules, report
export, and verification. It is synthetic: the account, host, address, and
paths are invented and no real evidence is involved.

`evidence/events.jsonl` contains, in order:

- five `auth.login_failed` records for `alice` via `sshd` on `web-01` within
  160 seconds;
- one `auth.login_succeeded` for the same account, service, and host;
- a `browser.download` and a `process.execute` that name the same path
  (`/home/alice/Downloads/tool.zip`) 50 seconds apart;
- two file-activity records for `/srv/config/app.yaml`.

The record time is RFC 3339, the event kind is declared in the record, and the
host, account, service, address, and path stay in the raw observation. No
adapter invents a kind or a time.

## Run it

From the repository root:

```bash
cargo build -p ghosttrace-cli --release
export PATH="$PWD/target/release:$PATH"

export WORK=/tmp/gt-failed-logon
rm -rf "$WORK" && mkdir -p "$WORK"

ghosttrace case create --case "$WORK/case.ghosttrace-case" --label failed-logon-timeline
ghosttrace scan --case "$WORK/case.ghosttrace-case" \
  --source samples/failed-logon-timeline/evidence --claimed-source "synthetic auth log"
ghosttrace import --case "$WORK/case.ghosttrace-case" --path events.jsonl \
  --format jsonl --time-field ts --time-format rfc3339 \
  --kind-field kind --host-field host --message-field msg

ghosttrace timeline --case "$WORK/case.ghosttrace-case" --kind auth.login_failed
ghosttrace search --case "$WORK/case.ghosttrace-case" --text '"Failed password"'
ghosttrace analyze --case "$WORK/case.ghosttrace-case"
ghosttrace report --case "$WORK/case.ghosttrace-case" --output "$WORK/reports" --csv
ghosttrace verify --case "$WORK/case.ghosttrace-case"
```

## Expected result

| Step | Result |
|---|---|
| `scan` | 1 object, 1875 bytes, 1 captured, 0 gaps, exit `0` |
| `import` | `state:"completed"`, 11 records, 11 observations, 11 events, 0 diagnostics, exit `0` |
| `timeline --kind auth.login_failed` | 5 rows |
| `search --text '"Failed password"'` | 5 rows |
| `analyze` | `state:"completed"`, exactly 2 findings, exit `0` |
| `report --csv` | 11 events, 0 gaps, `report.json`, `report.html`, `report.csv` |
| `verify` | `verified:true`, 1 object verified, `signed:false`, exit `0` |

The two findings are:

| Rule | Severity | Predicate | What it does *not* say |
|---|---|---|---|
| `auth.fail_then_success` | medium | 5 failures, same host/user/service, success 160 s later | whether the password was mistyped, a legitimate retry, or guessing |
| `process.download_then_execute` | low | same recorded path, 50 s apart | that the download caused the execution, or that the file was new |

The other three compiled rules are reported as `not_evaluated`, with reasons:

- `file.hash_changed_metadata_equal` needs two comparable captures; this case
  has one.
- `time.clock_discontinuity` needs two boot-scoped journal samples carrying both
  realtime and monotonic times; JSONL does not provide them.
- `activity.outside_declared_hours` is disabled until `--rules` supplies an
  explicit schedule.

There is no maliciousness score in any output. Severity is a fixed band, the
supporting event ids are recorded, and the alternatives remain visible.

## Clean up

```bash
rm -rf /tmp/gt-failed-logon
```
