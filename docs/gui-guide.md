# Desktop guide (P6.4)

The desktop application is a native egui/eframe shell over the same
`ghosttrace-core` service the CLI uses. P6.1 covers the case and evidence
workflow; P6.2 adds the timeline, histogram, and provenance inspector; P6.3
adds snapshot comparison, relationships, findings, notes, and saved views; P6.4
adds unredacted report export, manifest verification, and three appearance
palettes, completing the desktop workflow.

```bash
cargo run -p ghosttrace-desktop
cargo run -p ghosttrace-desktop -- --renderer wgpu   # optional backend
```

P9.1 adds manifest signing and signature-aware verification to the "Report and
verify" screen. The default renderer is glow (see `docs/adr/0001-native-rust-ui.md`). With the
`screenshot` cargo feature and the glow renderer, `EFRAME_SCREENSHOT_TO=shot.png`
writes one frame and exits.

## What works now

**Cases screen**

- Create a case by entering a directory ending in `.ghosttrace-case`, a label,
  and a display time zone. The directory must not exist; it is created private
  to the current user. The case id comes from the directory name, never from
  free-form input.
- Open an existing case. The case schema is migrated and backed up per
  `docs/storage.md`, and every recorded capture is listed newest first.
- Recovery review: if the case was closed while a job was still running, the
  interrupted job ids and their last committed locators are shown. Nothing is
  completed automatically and no evidence is invented; acknowledging the notice
  leaves the job recorded as recoverable. Continue by starting a new capture or
  import — the partial output stays visible.

**Import evidence screen**

- Capture a source directory as a protected copy or live best effort. The
  method's trade-off is stated next to the choice, the limits (depth, entries,
  bytes per file) are shown, and a one-line summary appears before starting.
  Roots that overlap the case store are rejected before anything is read.
- Import one captured object, with auto-detection or an explicit format. Syslog
  RFC 3164 time zone and year are optional and never inferred: leaving them
  empty keeps those times unresolved.
- One job runs at a time. Start buttons disable while it runs; Cancel acts on
  the running copy immediately and the recorded state becomes `cancelled`.

Every result is reported as recorded fact: capture object counts and coverage
gaps, import run id/state/event counts, or a stable error code with a message.
Raw evidence values, paths from artifacts, and case notes are not written to
the job line.

**Timeline screen**

- Filters: validated search text, exact kind/host/source, and the explicit
  unresolved-times view. Typing waits 350 ms before one query is issued; the
  query carries a generation number, and a page or detail that arrives after
  the filters changed is discarded.
- The time histogram declares its bin width and interval. Selecting a bin
  filters to that interval; Clear time window removes it. Events with no chosen
  time cannot be placed in a window and are counted in words beside the bins —
  they are never silently dropped.
- The event list is virtualized and pages in keyset order. At most 1,000 rows
  are cached; the status line says when the cache limit is reached and asks for
  narrower filters instead of quietly truncating.
- Every row states time status in words (`unresolved time`, `ambiguous time`,
  `invalid time`) rather than by color.
- Keyboard: `J`/`K` select the next/previous loaded event, `U` toggles the
  unresolved view, `/` moves focus into the search field. Controls are named for
  assistive technology, and the layout is checked at 1.5× scaling.

**Evidence inspector**

- Shows the selected event's parse run and parser version, every recorded time
  with its raw field/value, epoch, unit, precision, clock domain, and recorded
  assumptions, the scoped entities, and the parse run's own diagnostics.
- Raw records are opened from the recorded evidence/locator link. An event
  imported before that link existed says so instead of showing a guessed
  record.
- Copy actions exist for the event id, locator, and raw record. The raw preview
  is inert, escaped (control and bidi characters become visible escapes), and
  bounded; a truncated preview says so.
- Notes and tags are appended to the event id as a new revision that names the
  one it supersedes. A bookmark is a recorded `bookmark` tag, not a new fact.
  A concurrent edit is reported as a conflict, never overwritten.

**Compare captures screen**

- Choose the earlier and later recorded capture explicitly. The result states
  whether the scopes are compatible, both root sets, and every warning.
- Every row carries a class and a stable reason. `unknown` is its own class:
  a scope mismatch, coverage gap, or missing digest is never folded into
  "appeared" or "deleted". Move candidates are labelled as equal bytes only.
- Row detail shows the recorded size, digest, and mtime for each side. The list
  pages in keyset order; loading another page keeps the first page's scope
  verdict.

**Relationships screen**

- Candidate links derived from recorded entities, with the rule id/version,
  strength basis, matching fields, and supporting event ids. Opening a
  supporting event switches to the timeline inspector for its raw record.
- The list is the primary representation and is keyboard reachable (`J`/`K`).
  The graph draws at most 40 nodes and 80 edges over the same loaded rows; when
  it omits something it says so in text, and every loaded row stays in the list.
- "Derive relationships" runs on the single job worker because it records new
  facts; the read list runs on the query thread.

**Findings screen**

- Run the five compiled rules against the active revision. Each finding shows
  its severity band (never a score or percentage), rationale, named
  alternatives, recorded predicates, and supporting events.
- A disposition change appends a revision naming the one the analyst saw; the
  history shows author, time, text, tags, and disposition. A stale revision is
  a visible conflict.

**Saved views**

- The timeline can store the current typed filter (search text, exact
  kind/host/source, window, unresolved view) under a name. Applying a view
  restores those fields and re-runs the shared query path; stored views never
  contain SQL or an expression.

**Report and verification screen**

- Export the recorded report for one acquisition and revision through the same
  `reports::build_report`/`publish` path the CLI uses. The screen states the
  case label, display time zone, chosen acquisition, revision, and event limit
  before the button.
- **P6.4 exports unredacted reports.** Recorded values are included as stored;
  the redaction selection/preview workflow arrives with P9.2. The screen says
  this above the export control, not only in documentation.
- The destination must be an absolute path outside the case directory; an empty,
  relative, or in-case destination is refused with a visible reason before a job
  starts. A failed publication (for example an existing report id) stays on
  screen as `export failed: <code>: <message>`.
- Export is a job, so it appears in the job bar with the shared Cancel control.
  A cancel that arrives before the job starts publishes nothing.
- "Verify manifest" re-hashes every stored object of the latest (or chosen)
  acquisition manifest and compares it with the recorded digest. The result
  shows manifest id, acquisition, format, object count, bytes, captured count,
  and coverage gaps; a mismatch fails the job with its code instead of a
  success-shaped result.

**Appearance and layout**

- Dark (default), Light, and High contrast palettes, chosen in the header. High
  contrast uses a black background, white text, opaque selection, and thicker
  widget strokes so focus and selection never depend on hue alone. The choice
  is per session; no configuration file is written.
- The shell is an app bar (wordmark, case identity, appearance, screen tabs)
  over a status bar (job state as a worded chip plus progress), with each
  screen's content in raised cards: quiet section labels, metric tiles for
  counts, and state chips that always carry their own words. The palette
  tokens, metrics, and widget chrome live in `theme.rs` and are applied as one
  egui style per palette, so every screen shares them.
- Every screen has an explicit empty state (no case, no capture, no parse run,
  no findings, no relationships), a loading state on the job/query bar, and a
  failure state that keeps the error code and message visible.

## Architecture

- `theme.rs` — the palette tokens, metrics scale, and the egui `Style` each
  palette installs, plus the shared `card`/`section`/`chip`/`stat`/`primary`/
  `quiet` helpers. Widget chrome (buttons, fields, check boxes, combo boxes,
  scroll bars, selection) is styled once per palette; no meaning is ever
  carried by color without an accompanying word.
- `state.rs` — pure UI state and the command/result reducer. `apply()` drops
  results whose job id is no longer current.
- `commands.rs` — `Command`/`CommandEvent` messages and the single worker
  thread. Cancellation handles are shared atomics, so a cancel requested before
  the worker registers its handle is remembered rather than lost.
- `query.rs` — a second worker thread with its own read-only `CaseReader` for
  timeline pages, histogram aggregates, event details, diffs, relationships,
  findings, annotation history, and saved views. Queries never wait behind a
  running capture/import, and results carry their generation.
- `state.rs` — timeline, diff, relationship, and finding state: debounce
  deadline, bounded page caches, graph caps, selection, and per-area generation
  counters. `apply_query()` ignores superseded results and keeps failures
  actionable.
- `cases.rs`, `import.rs`, `timeline.rs`, `evidence.rs`, `diff.rs`,
  `relations.rs`, `findings.rs`, `report.rs` — screens. They only mutate state
  and queue requests.
- `app.rs` — `eframe::App`: `logic` drains job and query results, applies
  cancels, sends commands and queries; `ui` only draws. No SQLite or evidence
  access happens in a render callback.

## Testing

```bash
cargo test -p ghosttrace-desktop
```

`tests/desktop_case_workflow.rs` drives the real UI with `egui_kittest`,
addressing controls by accessible label and role (not pixel positions):
create case, invalid destination, method review, start, cancel, and recovery
acknowledgement. `tests/desktop_jobs.rs` runs the worker against a temporary
case: create → capture → import, pre-registered cancellation, and failure
codes. `tests/desktop_timeline.rs` covers debounce, supersession, the bounded
cache, bin selection, and detail replacement. `tests/desktop_accessibility.rs`
checks named controls, keyboard selection, the `/` shortcut, 1.5× scaling, and
that uncertainty appears in words. `tests/desktop_analysis.rs` covers diff
scope/unknown visibility and paging, findings dispositions, event notes and
bookmarks, saved views, and the analysis/correlation commands.
`tests/desktop_graph_limits.rs` covers the graph node/edge caps, keyset
expansion, keyboard selection, and the accessible edge names.
`tests/desktop_report.rs` covers the stated export scope and time zone,
destination validation, published/verified summaries, a failed publication,
and a pre-registered cancel that publishes nothing. `tests/desktop_jobs.rs`
also runs the real report export, manifest verification, and duplicate-report
refusal through the worker, and reopens the case to exercise the acquisition
query. Because a running job animates its progress bar, those tests step a
fixed number of frames instead of waiting for the UI to settle.

### Responsiveness (measured, not asserted from design)

A generated 1,000,000-event case (105 MiB JSONL, 1.5 GiB case store) was
imported with the release CLI, then the P6.2 read paths were timed
(`tests/scale_timeline.rs`, ignored unless `GHOSTTRACE_SCALE_CASE` is set):

| Path | Time |
|---|---|
| First timeline page (200 rows) | 1.0 ms |
| Next page via keyset cursor | 0.9 ms |
| Histogram (24 bins, exact counts) | 0.5 s |
| Event detail (raw record + times) | 1.0 ms |
| Full-text phrase search | 1.4 ms |

These numbers are from one local run on the reference profile in plan
Section 11; re-measure before publishing P10 reference figures. The histogram
is the slow path because exact counts aggregate the whole filtered revision; it
runs on the query thread, so the UI stays interactive while it arrives. The
same measurement exposed a search plan that evaluated `MATCH` once per event
(33 s for a rare term); the FTS subquery now drives the join, and
`storage::search` keeps a query-plan test so the regression cannot return
silently.

## Known limitations

- Recovery is review plus acknowledgement; resuming an interrupted copy is not
  offered because the original capture spec is not stored. Start a new capture.
- Progress is exact for capture (objects and bytes) and indeterminate for
  import, because the adapter does not expose a record counter to the UI.
- No native file dialogs yet: paths are typed or pasted, which keeps the
  workflow testable and avoids another dependency. Dialogs can be added when
  the standard path input proves insufficient.
- The histogram reports exact counts over the filtered revision, so it costs
  about half a second per million events; it is not sampled or approximated.
- Search uses the validated FTS grammar: hyphenated terms must be quoted
  (`"needle-rare"`), otherwise `-` means exclusion.
- Snapshot comparison re-reads both recorded snapshots for each page, so paging
  a very large comparison repeats that work; it is a manual, explicit action.
- Relationships are derived over every recorded entity, not per revision; the
  revision is stated where it applies, and a link's support names its events.
- Report export is unredacted until P9.2; do not hand a report to a third party
  without reviewing its recorded values.
- Report paging is bounded by the event limit you choose (default 500, maximum
  10,000 in the UI). The report states the limit in its provenance.
- Screen-reader verification on the release targets is a P10 gate. The earlier
  Orca smoke test failed on rootless Xwayland with an XKB error; that is an
  environment limitation, not an accessibility certification
  (`docs/releases.md`).

**Report and verify screen (P9.1)**

- Verification now reports three separate statuses: stored-object digests,
  signature validity (`absent`/`valid`/`invalid`), and key trust
  (`not_applicable`/`untrusted`/`trusted`), plus a capture-completeness line and
  a one-sentence explanation. A valid signature from an unknown key is shown as
  mathematically valid but untrusted; it is not hidden and it is not called a
  failure.
- Optional sidecar and trusted-key-list paths use the same files as the CLI.
- The "Sign manifest" section signs the exact stored manifest bytes with an
  encrypted key file. Entering a path that does not exist generates a new key
  (mode `0600`, never overwritten). The passphrase is a password field, is moved
  into the job, and is cleared immediately; it is never stored in the case or a
  report. An existing sidecar is never replaced.

**Redaction, packages, and backup/restore (P9.2)**

- The "Report and verify" screen has an explicit redaction selection (case
  label, source paths, object paths, timeline summaries, timeline hosts). The
  selection is stated before the button and applied only to the published copy;
  a `redaction.json` ledger lists fields and counts, never removed text. Every
  desktop export also writes `report.csv`.
- The same screen can back up the open case and restore a backup into a new
  directory. Restore verifies the inventory, database integrity, schema
  version, and every object reference before publishing, then opens the
  restored case.
