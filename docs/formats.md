# Log format catalog (P4.1)

Only the adapters in this table exist, and only the listed rules produce
events. Anything else is preserved as a raw observation or reported as a
structured diagnostic; no adapter invents an event type, a year, or a zone.

| Adapter id | Version | Detected by | Produces events |
| --- | --- | --- | --- |
| `jsonl.fields` | 1 | first non-space byte `{` or `[` | every valid mapped object |
| `syslog.rfc5424` | 1 | `<PRI>1 ` prefix | only the tested auth messages below |
| `syslog.rfc3164` | 1 | `<PRI>` without a `1 ` version | only the tested auth messages below |

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

## Bounds

| Bound | Default | Behavior when reached |
| --- | --- | --- |
| record bytes | 1 MiB (max 16 MiB) | `record_too_large` diagnostic, record skipped |
| records per import | 1,000,000 | `record_limit` diagnostic, run `partial` |
| stored diagnostics | 100 (count is exact) | `diagnostics_truncated` marker |

Batches commit every 500 records. Cancellation is checked between records; a
cancelled run is stored as `cancelled`, never as `completed`.

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

## Not supported (deliberate)

- Inferring RFC 3164 years from file mtimes, rotation names, or arrival order.
- Regular-expression or executable field mappings.
- Reordering or correlating events across hosts or boots.
- Interpreting structured data as fields; it is preserved as raw text.
- Any syslog pattern outside the table above.
