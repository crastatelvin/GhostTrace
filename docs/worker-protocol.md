# Isolated parser workers

Risky adapters decode attacker-controlled binary containers. They run in a
separate process so a malformed artifact cannot crash the desktop, corrupt the
case writer, or leave a run looking completed. This document is the contract;
the code is `crates/ghosttrace-core/src/worker/` and
`crates/ghosttrace-core/src/ingest/isolated.rs` (plan P8.2).

## Which adapters run isolated

| Adapter | Path |
|---|---|
| EVTX (`--format evtx`) | Isolated by default |
| Journal export (`journalctl -o export`) | Isolated by default |
| Browser package | In-process (see the limitation below) |
| JSONL, syslog | In-process (bounded text loops) |

The product never silently falls back: the CLI and the desktop require the
worker for the isolated formats. `--no-worker` on the CLI is a debugging switch
that says so out loud.

**Limitation, disclosed:** the browser adapter still runs in-process. It needs
the case's staged SQLite package and its own private copy, so moving it behind
the same record protocol is separate work; until then it is protected by its
read-only private copy, defensive SQLite settings, and a 30-second query
deadline, not by process isolation.

## Worker binary

The worker is the packaged CLI binary in a private mode (`ghosttrace worker
--protocol 1`). The parent resolves it explicitly:

- the CLI uses its own executable;
- the desktop uses the sibling `ghosttrace` beside `ghosttrace-desktop`
  (`bin/` in a release package);
- `--worker <path>` names one directly.

A missing, non-regular, or mismatched binary is an error. `PATH`, the evidence
directory, and the case directory are never searched.

The handshake carries a protocol version and the exact build version. Both must
match; a worker from another build is refused before any job is sent.

## Transport

One frame is a 4-byte big-endian length followed by that many bytes of JSON.
There is no other framing, no compression, and no out-of-band channel.

| Bound | Value |
|---|---|
| Control frame | 64 KiB |
| Batch frame | 32 MiB |
| Records per batch | 500 |
| Worker flush threshold | 1 MiB of record payload |
| Locator | 512 bytes, no control characters |
| Raw record | the job's `--max-record-bytes` (≤ 64 MiB) |
| Mapped fields | 256 KiB, JSON object |
| Event kind | 128 bytes, `[a-z0-9._-]` |
| Event summary | 4096 bytes |
| Named times per event | 8 |
| Candidates per time | 8 |
| Assumptions per time | 16 |
| Diagnostics per record | 32 |
| Adapter diagnostics | 100 stored, total counted |

A frame over its bound, a zero length, or a truncated body is a protocol
violation. Nothing is clamped and nothing is partially accepted.

### Messages

Parent to worker:

```json
{"type":"hello","protocol":1,"version":"0.1.0-alpha.1"}
{"type":"parse","job_id":"job-…","format":"evtx","path":"/private/staging/sysmon.evtx","max_records":1000000,"max_record_bytes":8388608}
```

Worker to parent:

```json
{"type":"ready","protocol":1,"version":"0.1.0-alpha.1"}
{"type":"progress","job_id":"job-…","records":1000}
{"type":"batch","job_id":"job-…","seq":0,"records":[ … ]}
{"type":"done","job_id":"job-…","records":358,"observations":358,"events":358,"diagnostics":[…],"diagnostics_total":8}
{"type":"failed","job_id":"job-…","code":"unsupported_format","message":"…"}
```

The parent validates every message: the job id must match, batch sequence
numbers must increase from zero, batches must be non-empty and within the
record limit, each record must pass the bounds above, and `done` must report
exactly the counts the parent committed. Any mismatch fails the run.

### Record wire shape

`raw_json` is the adapter's record as a JSON object, or — for the journal
adapter — an ordered array of `[name, value]` pairs. `mapped_json` is always an
object. Locator kinds are limited to `byte_range`, `logical_row`,
`binary_record`, and `filesystem_entry`; a worker cannot introduce a kind the
storage schema rejects.

Raw numeric times are `i128` internally, which `serde_json` cannot deserialize,
so they travel as exact decimal strings and are parsed back during validation.
A non-numeric string is a protocol error.

## Process controls

- The child gets a cleared environment (`env_clear`), a private working
  directory, piped stdin/stdout, and a null stderr.
- The input is a **copy** of the captured object in a fresh `0700` temporary
  directory, made after the digest was verified. The worker never receives a
  path into the case store. The copy is removed when the job ends, success or
  not.
- The worker validates its own input path: absolute, regular, not a symlink,
  and inside its private directory.

On Linux the child also gets:

| Control | Value |
|---|---|
| New session (`setsid`) | A kill reaches the whole process group |
| `PR_SET_NO_NEW_PRIVS` | No privilege gain through setuid binaries |
| `RLIMIT_AS` | 1 GiB |
| `RLIMIT_CPU` | 600 s |
| `RLIMIT_FSIZE` | 1 GiB |
| `RLIMIT_NOFILE` | 128 |
| `RLIMIT_CORE` | 0 |

The parent kills the worker when it produces no frame for 30 seconds
(`--worker-timeout` is not exposed; tests shorten it) or when the whole job
exceeds 30 minutes. Cancellation kills the worker and records the run
`cancelled`.

## Failure semantics

| Situation | Run state | Diagnostic |
|---|---|---|
| Worker missing, mismatched, or unstageable | `failed` | `worker_start_failed` |
| No frame within the deadline | `failed` | `worker_timeout` |
| Worker exits before `done` | `failed` | `worker_crashed` |
| Bad frame, bad record, wrong job/sequence/counts | `failed` | `worker_protocol` |
| Worker reports an adapter error | `failed` | `worker_error` |
| Worker reports success with diagnostics | `partial` | the adapter's codes |
| Worker reports success without diagnostics | `completed` | — |

Records committed before a failure stay in the case and the run says `failed`.
A malformed artifact can therefore never produce a completed run, and a hung
worker cannot block the caller.

## What is not sandboxed

Stated plainly, because assuming more would be worse than knowing:

- **No network namespace or seccomp filter.** A compromised worker process
  could open sockets. The adapters never do, and the worker is only sent a
  staged copy, but there is no kernel-level network denial.
- **No filesystem namespace.** The worker can read world-readable files on the
  host. It never gets the case path or the evidence path.
- **macOS and Windows get no resource limits.** They get the cleared
  environment, the private working directory, and the pipe protocol only.
- **Staging costs one copy of the object** before parsing.

These are the honest limits of this phase; a stronger sandbox (seccomp,
namespaces, or platform job objects) is future work, not a claim made here.
