# Desktop guide (P6.1)

The desktop application is a native egui/eframe shell over the same
`ghosttrace-core` service the CLI uses. P6.1 covers the case and evidence
workflow; the timeline, inspector, findings, and reports screens arrive in
P6.2–P6.4.

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

## Architecture

- `state.rs` — pure UI state and the command/result reducer. `apply()` drops
  results whose job id is no longer current.
- `commands.rs` — `Command`/`CommandEvent` messages and the single worker
  thread. Cancellation handles are shared atomics, so a cancel requested before
  the worker registers its handle is remembered rather than lost.
- `cases.rs`, `import.rs` — screens. They only mutate state and queue commands.
- `app.rs` — `eframe::App`: `logic` drains results, applies cancels, sends
  commands; `ui` only draws. No SQLite or evidence access happens in a render
  callback.

## Testing

```bash
cargo test -p ghosttrace-desktop
```

`tests/desktop_case_workflow.rs` drives the real UI with `egui_kittest`,
addressing controls by accessible label and role (not pixel positions):
create case, invalid destination, method review, start, cancel, and recovery
acknowledgement. `tests/desktop_jobs.rs` runs the worker against a temporary
case: create → capture → import, pre-registered cancellation, and failure
codes. Because a running job animates its progress bar, those tests step a
fixed number of frames instead of waiting for the UI to settle.

## Known limitations

- Recovery is review plus acknowledgement; resuming an interrupted copy is not
  offered because the original capture spec is not stored. Start a new capture.
- Progress is exact for capture (objects and bytes) and indeterminate for
  import, because the adapter does not expose a record counter to the UI.
- No native file dialogs yet: paths are typed or pasted, which keeps the
  workflow testable and avoids another dependency. Dialogs can be added when
  the standard path input proves insufficient.
- Screen-reader verification on the release targets is a P10 gate. The earlier
  Orca smoke test failed on rootless Xwayland with an XKB error; that is an
  environment limitation, not an accessibility certification
  (`docs/releases.md`).
