# EVTX fixtures (P8.1)

Real Windows event logs from the public sample set of the
[`evtx`](https://github.com/omerbenamram/evtx) parser project, redistributed
under that project's MIT OR Apache-2.0 licence. They contain no credentials and
no case material; they are parser test samples.

| file | upstream sample | sha256 | used for |
|---|---|---|---|
| `security-failure.evtx` | `Security_short_selected.evtx` | `50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456` | Security 4625 (failed logon), 4776, and unknown Security events that must stay generic |
| `security-success.evtx` | `security.evtx` | `5f29a03cf8c1b4bfbd82c4074ccc81ecfe85d7ee15375afc352ed5025c9a4d8d` | Security 4624 (successful logon) mapping and rule input |
| `sysmon.evtx` | `sysmon.evtx` | `e1817fd7241ad2b5b9660e179adec878d157f1fa25333e52aef263c69bcd970b` | Sysmon 1 process creation (path, SHA256, payload `UtcTime`), plus unreadable chunks used by the truncated/corrupted tests |

Source URL pattern:
`https://raw.githubusercontent.com/omerbenamram/evtx/master/samples/<upstream sample>`.

`sysmon.evtx` is 1,118,208 bytes: a 4 KiB header plus 17 complete 64 KiB
chunks, 8 of which are unreadable. The import must report those and end as
`partial`, never as a completed run.

A prefix of the file is used to test truncated evidence. The chunk area of a
truncated file is not a whole number of 64 KiB chunks, which is the signal the
adapter uses; the header's own chunk counter is stale on dirty logs (this file
says "1 chunk" while holding 17), so it is not trusted. A prefix cut exactly on
a chunk boundary is indistinguishable from a shorter complete log and is not
claimed as truncation.

The files are tracked because a synthetic EVTX would only prove that the test
and the parser agree on invented bytes; these are real records from real
Windows systems.
