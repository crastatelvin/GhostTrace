# Desktop guide (P6.2)

The desktop application is a native egui/eframe shell over the same
`ghosttrace-core` service the CLI uses. P6.1 covers the case and evidence
workflow; P6.2 adds the timeline, histogram, and provenance inspector.
Diff, relationships, findings, and reports arrive in P6.3–P6.4.

```bash
cargo run -p ghosttrace-desktop
cargo run -p ghosttrace-desktop -- --renderer wgpu   # optional backend
```

The default renderer is glow (see `docs/adr/0001-native-rust-ui.md`). With the
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

## Architecture

- `state.rs` — pure UI state and the command/result reducer. `apply()` drops
  results whose job id is no longer current.
- `commands.rs` — `Command`/`CommandEvent` messages and the single worker
  thread. Cancellation handles are shared atomics, so a cancel requested before
  the worker registers its handle is remembered rather than lost.
- `query.rs` — a second worker thread with its own read-only `CaseReader` for
  timeline pages, histogram aggregates, and event details. Queries never wait
  behind a running capture/import, and results carry their generation.
- `state.rs` — timeline state: debounce deadline, bounded page cache, histogram,
  selection, and generation counters. `apply_query()` ignores superseded
  results and keeps failures actionable.
- `cases.rs`, `import.rs`, `timeline.rs`, `evidence.rs` — screens. They only
  mutate state and queue requests.
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
that uncertainty appears in words. Because a running job animates its progress
bar, those tests step a fixed number of frames instead of waiting for the UI to
settle.

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
- Screen-reader verification on the release targets is a P10 gate. The earlier
  Orca smoke test failed on rootless Xwayland with an XKB error; that is an
  environment limitation, not an accessibility certification
  (`docs/releases.md`).
