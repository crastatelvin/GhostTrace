# Log format fixtures (P4.1)

The adapter tests generate their inputs deterministically from the definitions
below; no third-party or real log data is tracked.

## JSONL

```
{"ts":"2026-10-27T10:00:00Z","msg":"hello"}
{"ts":1793095200,"kind":"file.read","host":"host-a","msg":"read report"}
{"msg":"no time here"}
{"ts":"not-a-time"}
{"ts":"2026-10-27T10:00:00Z","kind":42}
```

Expected: the first two are accepted (RFC 3339 and unix-seconds variants), the
third is accepted with an `unresolved` time, the fourth is accepted with an
`invalid` time, and the fifth is preserved raw with `schema_mismatch` and no
event. `[1,2,3]` and `not json` are reported, not coerced.

## Syslog

```
<34>1 2026-10-27T10:00:00.123Z host sshd 1234 ID47 [exampleSDID@32473 iut="3"] Accepted publickey for alice from 10.0.0.5 port 2222 ssh2
<34>Oct 27 10:00:00 host sshd[123]: Accepted password for bob from 10.0.0.6 port 22 ssh2
<34>Oct 25 02:30:00 host sshd[1]: Accepted password for bob from 10.0.0.6 port 22 ssh2
<34>Oct 27 10:00:00 host myapp[1]: service started
<34>Oct 27 10:00:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
```

Expected: the RFC 5424 record resolves `123 ms` and maps `auth.login_succeeded`;
the RFC 3164 records stay `unresolved` without `--year`/`--timezone`, resolve
with both supplied, and become `ambiguous` at the DST overlap on 2026-10-25
02:30 Europe/Berlin; the unmatched `myapp` message stays a raw observation; the
sudo record maps `auth.sudo_command`. A December→January pair with `--year 2025`
marks the January record ambiguous between 2025 and 2026.
