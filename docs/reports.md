# Verification and reports

Two commands close the loop on a captured case:

- `ghosttrace verify` re-reads a stored acquisition manifest and re-hashes the
  stored objects. When a detached signature is present it also checks the exact
  manifest bytes and reports signature validity and key trust separately. An
  unsigned check proves the bytes still match the record, not who produced the
  record; a valid signature from a key that is not in your trusted list proves
  only that the key signed those bytes.
- `ghosttrace report` exports a versioned JSON report and a self-contained HTML
  view built only from the recorded case.

Nothing in either command reads the evidence source again, uploads anything, or
resolves a URL.

## `ghosttrace verify`

```bash
ghosttrace verify --case /cases/investigation.ghosttrace-case
ghosttrace verify --case … --acquisition acq-…
ghosttrace verify --case … --manifest /cases/investigation.ghosttrace-case/manifests/manifest-acq-….json
ghosttrace verify --case … --trust ~/trusted-keys.txt
```

Signing is documented in [cli.md](cli.md#sign) and the sidecar/key formats in
[formats.md](formats.md#signing-keys-and-detached-signatures-p91).

Without `--manifest`, the command verifies the manifest of `--acquisition`, or
of the newest acquisition. Success prints one JSON line:

```json
{"verified":true,"manifest_id":"manifest-acq-…","acquisition_id":"acq-…",
 "format":"ghosttrace-manifest/1","objects_verified":3,"total_bytes":22,
 "captured":3,"gaps":0,"signed":false}
```

Exit codes: `0` verified, `4` the manifest did not verify, `1` the file or case
could not be read, `2` invalid usage.

Verification fails closed on:

| Condition | Machine code |
| --- | --- |
| any stored object's bytes differ from its digest | `integrity_mismatch` |
| a referenced object is missing from the store | `corrupt_evidence` |
| malformed JSON, duplicate JSON keys, unknown format version | `unsupported_format` |
| duplicate object IDs or store paths | `unsupported_format` |
| a `store_subpath` outside `objects/sha256/<bucket>/<hex>` | `unsupported_format` |
| a signature that does not cover the exact manifest bytes | `integrity_mismatch` |
| unsupported signature format/algorithm, malformed hex, fingerprint mismatch | `unsupported_format` |

Recorded coverage gaps (`gaps > 0`) do **not** fail verification: they are part
of the honest record, not tampering. A cancelled acquisition writes no manifest;
verifying it reports a missing file.

## `ghosttrace report`

```bash
ghosttrace report --case /cases/investigation.ghosttrace-case \
  --output /cases/reports [--acquisition acq-…] [--limit 500] [--report-id name]
```

The command prints the publication summary and writes a directory:

```
/cases/reports/<report-id>/report.json
/cases/reports/<report-id>/report.html
```

`report-id` defaults to `report-<acquisition-id>-<unix-seconds>`. It may contain
only letters, digits, `-`, `_`, and `.`; anything else is a usage error.

### What the report contains

- `format` (`ghosttrace-report/1`) so consumers can version-gate.
- Case identity: label, case ID, display timezone (never applied to source
  timestamps).
- Acquisition: method, claimed source, state, link policy, roots (encoded
  paths), start/end in capture-clock seconds.
- Coverage: counts for every status plus a bounded list of gap rows
  (`gaps_complete: false` when truncated).
- Objects: every captured path with its full SHA-256 and byte length.
- `revision`: the parse run whose events the timeline shows.
- Timeline: events of that revision, in chosen-time order, limited by
  `--limit` (recorded in `provenance.timeline_selection`).
- Provenance: generator, tool version, method, claimed source, link policy,
  roots, and `signed: false`. `generated_by` names the front end that built the
  report (`ghosttrace-cli` or `ghosttrace-desktop`); it is never hard-coded to a
  tool that did not run.

The timeline is pinned to exactly one revision. A re-import records a new
revision rather than replacing the earlier one, so pinning is what makes a
report reproducible: passing the same `--revision` again produces the same
timeline, and rebuilding with no `--revision` selects the newest parse run
deterministically. A report never mixes two revisions' events.
- Limitations: fixed, human-readable statements, plus a partial-results
  statement whenever coverage gaps exist.

The JSON report is full fidelity: labels and claim text are stored exactly as
recorded (JSON escaping still applies). The HTML view is the safe presentation
layer.

The desktop "Report and verify" screen calls the same builder and publisher, so
the CLI and GUI produce the same format from the same recorded rows. P6.4
exports **unredacted** reports from both front ends; redaction selection and
preview arrive with P9.2. The desktop refuses a destination that is empty,
relative, or inside the case directory, and a second export of the same report
id fails instead of overwriting.

### HTML safety

The HTML file is self-contained and inert:

- no `<script>`, no `<a>`, no `href`/`src` attributes, no remote resources;
- a `default-src 'none'` Content-Security-Policy meta tag;
- every value HTML-escaped (`&`, `<`, `>`, `"`, `'`);
- C0/C1 controls and Unicode bidi/format controls (`U+202A..U+202E`,
  `U+2066..U+2069`, `U+FEFF`, …) rendered as visible `\u{...}` escapes, so a
  hostile name is readable but cannot reorder or control the display;
- paths are root-qualified encoded paths, not raw bytes, and are never links.

`docs/reports.md` is the contract; the test suite rejects a rendered report that
contains active content or a surviving control character.

### Publication is atomic and append-only

Reports are staged in a private temporary directory inside `--output`, synced,
and renamed into place. A failure removes the staging directory, so there is no
half-written export that looks complete. An existing report directory is never
overwritten: re-running with the same `--report-id` fails with exit `1` and
leaves the previous report byte-identical.

## Packaging prereleases

`xtask package` builds a checksummed archive from an already-built binary:

```bash
cargo build -p ghosttrace-cli --release
cargo run -p xtask -- package --output dist --version 0.1.0-alpha.1
```

The archive contains `bin/ghosttrace`, both licences, `README.md`, the CLI and
report docs, `help.txt` captured from the binary itself, a small `sample/`
folder, and `build-info.json` with the version, target triple, rustc version,
git commit, and a SHA-256 for every packaged file. A sibling
`<archive>.sha256` file records the archive digest. Existing archives are never
overwritten, and no network access is involved.

Receivers verify before extracting:

```bash
sha256sum -c ghosttrace-0.1.0-alpha.1-<target>.tar.gz.sha256
tar -xzf ghosttrace-0.1.0-alpha.1-<target>.tar.gz
./ghosttrace-0.1.0-alpha.1-<target>/bin/ghosttrace --help
```
