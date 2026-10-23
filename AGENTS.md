# GhostTrace — repository instructions for agents

## Source of truth

`docs/plans/2026-10-23-ghosttrace-master-plan.md` is the specification. Read the
sections a task consumes before touching code (Section 16 "Repeatable task loop").
Phases run in order P0 → P12; do not start a phase before the previous phase's
stated gate passes. Track progress in the Section 18 table of that document.

## Rules that override general defaults

- **Evidence safety.** Source evidence is opened read-only and never modified.
  Captured bytes are immutable. Raw evidence, paths, URLs, and case notes never
  enter logs, reports, or diagnostics unless explicitly exported after preview.
- **Honest uncertainty.** Never convert an unknown timestamp, missing hash,
  incomplete traversal, or parser failure into a silent success. UI/report text
  must distinguish observed fact from inference; no uncalibrated "maliciousness
  percentage" anywhere.
- **No new dependencies** unless Section 3 of the plan names them. Smallest
  verified feature sets only.
- **No network by default.** The application never uploads evidence or fetches
  URLs from artifacts.

## Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run -p xtask -- check
```

## Commits and PRs

- Use the exact commit message listed for each task in Section 17 of the plan.
- Stage explicit paths; never `git add .` (case evidence/secrets may exist in
  the working folder). Review `git diff --cached` before committing.
