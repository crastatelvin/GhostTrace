# Contributing to GhostTrace

Thanks for helping build a forensic tool people can trust with evidence.
Trustworthiness includes the repository itself: no surprises in diffs, no
unverifiable dependencies, no evidence or secrets in history.

## Ground rules

1. **Read the plan first.** `docs/plans/2026-10-23-ghosttrace-master-plan.md`
   is the specification; `AGENTS.md` summarizes the rules agents follow.
2. **Phases are sequential.** Do not start a phase before the previous phase's
   stated gate passes. Merge order follows Section 16's critical sequence.
3. **No new dependencies** unless Section 3 of the plan names them, or an ADR
   is accepted that adds them. Prefer the standard library and existing
   workspace utilities.
4. **Evidence safety.** Never commit captured evidence, local case stores,
   source-machine paths, private keys, or logs containing raw evidence paths,
   URLs, or messages. `xtask check` enforces the tracked-path policy.
5. **Stage explicit paths.** `git add .` is forbidden when the working folder
   may contain case data; run `git diff --cached` before every commit.

## Development loop

```bash
rustup show                              # pinned toolchain (rust-toolchain.toml)
cargo run -p xtask -- check              # the whole battery, same as CI
cargo test -p ghosttrace-core --test <name> --locked   # focused tests
```

See `docs/testing.md` for the test strategy and `docs/quickstart.md` for
platform build prerequisites. Use the task's planned commit message from plan
Section 17 verbatim.

## Pull requests

- One reviewable deliverable per PR; branch names include phase/task
  (`feat/p2-1-safe-capture`).
- Use the PR template: behavior change, supported inputs/limits, tests run
  (with OS), compatibility impact.
- CI must pass. Reviewers check trust boundaries, evidence wording,
  cancellation, provenance, and compatibility — not just that tests pass.
- Heavy corpora, fuzzing, and benchmarks are not PR gates; they run on
  maintainer schedules (plan Sections 14, 16).

## What is out of scope for 1.0

Raw disk images, memory analysis, deleted-record carving, cloud sync,
arbitrary plugins, AI attribution, and similar capabilities are documented
future work, not this repository. See plan Sections 2 and 21 before proposing
them.

## Conduct

Be rigorous and respectful. `CODE_OF_CONDUCT.md` applies to all project
spaces.
