# Installation and first run

GhostTrace runs offline. There is no installer service, no account, no
auto-update, and no network listener. You build it from source or unpack a
release archive and run the binaries from a directory you choose.

## Supported platform

Linux x86_64 is the only platform with build-and-run evidence in this revision.
Windows and macOS are intended targets but remain unverified release-gate items;
see [releases.md](releases.md) for the matrix and the exact gaps. Do not treat a
successful cross-compile as support.

## Build from source

Prerequisites, the pinned Rust toolchain, and desktop libraries are listed in
[quickstart.md](quickstart.md). In short:

```bash
git clone https://github.com/crastatelvin/GhostTrace.git
cd GhostTrace
rustup show
cargo build --workspace --locked --release
cargo run -p xtask -- check
```

Binaries land in `target/release/`:

| Binary | Purpose |
|---|---|
| `ghosttrace` | CLI: case lifecycle, capture, import, timeline, search, diff, rules, reports, packages, backup/restore, verification, signing, TUI |
| `ghosttrace-desktop` | Native desktop workbench |

`cargo run -p ghosttrace-desktop` is equivalent to running the desktop binary.
Use `--release` for real investigations; debug builds are much slower at ingest
and hashing.

## Install from a release archive

A prerelease archive is built with:

```bash
cargo build --release -p ghosttrace-cli -p ghosttrace-desktop
cargo run -p xtask -- package --output dist --version 1.0.0-rc.2
```

The result is `dist/ghosttrace-<version>-<target>.tar.gz` and a sibling
`.sha256`. Verify, unpack, and run:

```bash
sha256sum -c ghosttrace-1.0.0-rc.2-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf ghosttrace-1.0.0-rc.2-x86_64-unknown-linux-gnu.tar.gz
./ghosttrace-1.0.0-rc.2-x86_64-unknown-linux-gnu/bin/ghosttrace --help
./ghosttrace-1.0.0-rc.2-x86_64-unknown-linux-gnu/bin/ghosttrace-desktop --version
```

The archive contains both binaries, the licences, the user guides, the tracked
synthetic samples, `help.txt`, `completions/`, `sbom.cdx.json` (a CycloneDX 1.5
inventory of the resolved Cargo graph), and `build-info.json` with the commit,
toolchain, target, and build facts. It does not modify `PATH`, install a
service, or write outside the directory you run it from.

Shell completions are also available directly from the binary:

```bash
ghosttrace completions bash > ~/.local/share/bash-completion/completions/ghosttrace
ghosttrace completions zsh  > ~/.zsh/completions/_ghosttrace
ghosttrace completions fish > ~/.config/fish/completions/ghosttrace.fish
```

**Unsigned builds are normal.** The source and binaries are free. Platform
trust is separate: Apple Developer ID/notarization and commercially trusted
Windows signing may cost money, and this project does not promise a
zero-cost universally trusted installer. Use the checksum, build from source,
or verify a detached signature when one is published. No feature is held back
for payment, and no subscription is needed to operate GhostTrace.

## First case

Create a case, capture a source, and inspect it:

```bash
ghosttrace case create --case /cases/demo.ghosttrace-case --label demo
ghosttrace scan --case /cases/demo.ghosttrace-case --source /evidence/export
ghosttrace status --case /cases/demo.ghosttrace-case
```

Then either import a captured log object (`ghosttrace import --help`), compare
two captures (`ghosttrace diff --help`), or run the compiled rules
(`ghosttrace analyze --help`). The ten-minute folder walkthrough is
[walkthrough.md](walkthrough.md); two tracked synthetic investigations are in
[`samples/`](../samples/README.md).

Open the same case in the desktop app with **Open case**, or browse it in a
terminal:

```bash
ghosttrace tui --case /cases/demo.ghosttrace-case
```

The TUI needs a terminal on both stdin and stdout; redirected output exits `2`
instead of emitting ANSI bytes. The desktop needs a working display server
(X11/Wayland); the default renderer is glow, with an optional `wgpu` build.

## Where data lives

- **Cases** are directories you name, ending in `.ghosttrace-case`. Nothing is
  written to a global database. The directory is created private to the current
  user and contains the SQLite database, captured objects, manifests,
  diagnostics, and reports.
- **Signing keys** are encrypted PKCS#8 PEM files you choose, for example
  `~/keys/signing.pem`. They are never stored inside a case, and a key file is
  never overwritten.
- **Trusted fingerprints** are a plain text file outside the case. Trust is a
  user preference, not evidence, and it is excluded from backups and packages.
- **Reports, packages, and backups** are written to explicit output
  directories; publication is atomic and never overwrites an existing result.

Uninstalling means removing the binaries and any cases you no longer need.
There is no registry, service, or hidden state to clean up.

## Upgrading a case

Opening an older case runs checksummed migrations. Before changing an existing
schema, the application takes a validated SQLite backup under the case's
`diagnostics/`; if that backup fails, the migration aborts before any schema
change. A case whose schema is newer than the running build is rejected, never
downgraded. See [storage.md](storage.md#schema-and-migrations).

Re-importing the same object with different time assumptions records a new
revision instead of overwriting the old one, so old reports stay reproducible.

## Signing, custody, and licensing

- A manifest signature proves that a specific Ed25519 key signed the exact
  stored manifest bytes. It does **not** prove when collection happened, that
  the host was truthful, or that custody was legally sufficient. Verification
  reports byte integrity, signature validity, and key trust separately; a valid
  signature from an unknown key is accepted and labelled `untrusted`.
- Signing keys are local and free. The optional paid parts are platform
  installer trust (Apple notarization, commercial Windows signing), not
  GhostTrace features.
- Source and binaries are dual-licensed Apache-2.0 or MIT, at your option.
  Fonts, fixtures, and bundled third-party material carry their own notices.
- Signing mechanics and trust-file format: [formats.md](formats.md#signing-keys-and-detached-signatures).
  What a signature does and does not establish: [threat-model.md](threat-model.md).

## What is not supported

Raw disk and memory acquisition, native systemd `.journal` files, the Windows
registry, MFT, prefetch, arbitrary parser plugins, cloud collaboration, and any
"maliciousness" score are deliberately out of scope. The exact supported
formats and their tested mappings are in [formats.md](formats.md); the
limitations are collected in [limitations.md](limitations.md).

If something fails, start with [troubleshooting.md](troubleshooting.md).
