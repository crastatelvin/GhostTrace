# Synthetic sample investigations

Tracked, reproducible data for learning the workflow and for testing documented
commands. Everything here is synthetic; no real evidence, personal data, or
third-party case material is included.

| Sample | Shows |
|---|---|
| [`failed-logon-timeline/`](failed-logon-timeline/README.md) | JSONL import, exact timeline/search filters, two compiled-rule findings, honest `not_evaluated` outcomes, report export, verification |
| [`misleading-snapshots/`](misleading-snapshots/README.md) | two captures of one folder, equal-metadata content change, move candidates, a coverage gap that stays `unknown`, partial-capture verification |

Both samples build a scratch case under `/tmp` and leave the tracked files
untouched. They reference only the tracked `evidence/` and `fixture/` files in
this directory; the scripts set mtimes and permissions explicitly because Git
does not preserve them.

For a folder-only walkthrough without logs, see
[`docs/walkthrough.md`](../docs/walkthrough.md). For the command reference, see
[`docs/cli.md`](../docs/cli.md).
