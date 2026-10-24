# Timestamp semantics

This document defines what a timestamp means in GhostTrace and how uncertainty
is carried. It is the human-readable companion of the rules embodied in
`ghosttrace-core/src/domain/time.rs`; where they disagree, the code is wrong.

## Representation

A normalized instant is **exact signed Unix seconds plus integer nanoseconds**.
Everything is *not* stored as one signed nanosecond integer: its date range is
too narrow for some forensic inputs (plan Section 6). The original value is
always preserved beside the normalization (`RawTimeValue`): field name,
integer or text, epoch, unit, and declared precision.

Epochs supported by the value model:

| Epoch | Meaning | Examples |
|---|---|---|
| `Unix` | seconds since 1970-01-01Z | Unix `mtime`, Firefox PRTime (micros) |
| `WindowsFileTime1601` | 100 ns intervals since 1601-01-01 | FILETIME, registry times |
| `Chrome1601` | microseconds since 1601-01-01 | Chromium visits/downloads |
| `MacAbsolute2001` | seconds since 2001-01-01 | macOS absolute times |

Fixed semantic checks (exactly these, not approximations):

- Chromium `11644473600000000` µs normalizes to the Unix epoch.
- Windows `116444736000000000` ticks normalize to the Unix epoch.
- Firefox `1000000` µs normalizes to one second after the epoch.

## Statuses

| Status | Meaning |
|---|---|
| `Resolved` | exactly one candidate instant |
| `Ambiguous` | more than one genuine interpretation (kept in chronological order) |
| `Unresolved` | not determined — a missing time is **not** epoch zero |
| `Invalid` | the value exists but cannot be interpreted (overflow, malformed) |

The displayed status never upgrades a time: an ambiguous DST reading stays
ambiguous, and an unresolved value stays unresolved until a recorded
correction resolves it.

## Local time rules

- A local wall-clock time is only interpreted with a **declared zone**. The
  analyst workstation's timezone is never silently assumed; a legacy syslog
  record without zone/year stays `Unresolved` and its missing pieces are
  recorded as explicit assumptions pending investigator input.
- A DST overlap (e.g. New York `2024-11-03 01:30`) keeps **both** UTC
  candidates: `05:30Z` and `06:30Z`.
- A nonexistent local time (spring-forward gap, e.g. New York
  `2024-03-10 02:30`) stays `Unresolved` unless a recorded correction
  resolves it.
- Negative dates (before 1970) are exact values, not errors.

## Semantic meaning by field

- Unix `mtime` — content modification time.
- Unix `ctime` — status/metadata change time (not creation).
- Birth time — optional; absence is reported as unknown, not zero.
- Access time — may be deferred, disabled, or affected by collection; a
  missing `atime` carries no implied event.
- Windows FILETIME semantics — filesystem behavior and delayed access updates
  affect interpretation; the value is kept exact, the caveat is carried as
  diagnostics rather than a silent correction.
- Chromium — microseconds since 1601 for visits/downloads; schema-specific
  exceptions are preserved per table.
- EVTX — `TimeCreated` is the logging time; payload occurrence time is a
  separate field. (Adapter arrives in P8; the domain already separates the
  semantic names.)
- Journal — realtime and monotonic times are separate clocks. Monotonic
  ordering applies only within one boot clock domain.

## Precision is not accuracy

`declared_precision` states what the *format* supports (nanos/micros/millis/
seconds/minutes/unknown). It never asserts measured clock accuracy. Clock
corrections are explicit analysis inputs with investigator attribution and
rationale, never background adjustments.

## Unresolved-time query behavior (contract)

- Timeline queries display the case display zone (UTC until the investigator
  chooses otherwise) and an uncertainty badge whenever the row's time is not
  `Resolved`.
- Unresolved events are never silently dropped from a timeline. They remain
  reachable in an explicit "unresolved time" view (implemented with the query
  contract in P1.2 and surfaced by the CLI `timeline`/desktop in later
  phases).
- Stable display sorting uses the chosen candidate, then source ID, then
  record identity; equal or overlapping uncertain times do not establish a
  proven order.
- `timeline --last 24h` anchors to the latest resolved event in the selected
  case, displays the anchor, and accepts `--until` for an explicit instant.
