# Troubleshooting

Start with the machine-readable error, not the prose. The CLI prints a stable
`code` in its JSON error and uses the exit codes below; the desktop shows the
same code. Never paste real evidence, source paths, or case notes into a public
issue — reproduce with the synthetic samples or a fixture.

| Exit | Meaning |
|---|---|
| `0` | accepted / completed |
| `1` | the operation failed (storage, corrupt evidence, key, permission) |
| `2` | invalid usage or configuration; nothing was recorded |
| `3` | completed with diagnostics, a coverage gap, truncation, or cancellation |
| `4` | verification failed (manifest, signature, package, or backup) |

| Code | Usually means |
|---|---|
| `permission` | a file, directory, key, or trust list is not readable/writable by this user, or a key has unsafe permissions |
| `storage` | SQLite or filesystem failure, including a full disk or a busy database |
| `schema_incompatible` | the case schema is newer than this build, a migration was edited, or the pre-migration backup failed |
| `integrity_mismatch` | bytes differ from the recorded digest, or a signature does not cover the exact manifest/package bytes |
| `corrupt_evidence` | a referenced object or manifest is missing or malformed |
| `unsupported_format` | a format, version, cipher, KDF, or option is deliberately not accepted |
| `input_changed` | the source changed during a read or capture; nothing was trusted |
| `resource_limit` | a configured depth/entry/byte/record bound was reached, or free space is below the required reserve |
| `conflict` | a concurrent edit moved the state the change was based on |
| `cancelled` | the user cancelled the job; committed work stays visible |
| `invalid_request` | malformed filters, rules, paths, or arguments |

## Capture reports a gap or exits 3

A gap is an honest record, not necessarily an error. Common coverage codes:

| Code | Action |
|---|---|
| `permission_denied`, `open_failed` | run the capture as a user that can read the source, or capture from a protected copy with the right ACLs; do not change evidence permissions just to make a scan green |
| `symlink_not_followed` | expected: links are recorded, not followed. Capture the target explicitly if it is in scope |
| `special_file` | sockets, devices, and FIFOs are not copied |
| `metadata_changed`, `vanished` | the source changed while it was read. Stop writes, recapture, and compare; the earlier object is still hashed and immutable |
| `traversal_limited` | a depth/entry bound was hit. Narrow the source or raise the documented limit deliberately |
| `deduplicated_hardlink` | two paths shared one inode; the bytes are stored once and the alias is recorded |

Exit `3` means the acquisition is partial. The manifest and verification remain
valid for the captured scope; `verify` reports `capture_complete:false`. Absence
from a partial scope is **not** evidence of deletion, and the diff marks it
`unknown`.

Running as root can read files a normal user cannot, but it also changes what
the capture means. Record the user and method; `--method live-best-effort` is
always labelled.

## `database is locked` or a case will not open

- One writer owns a case at a time. Close the other desktop window, CLI command,
  or TUI before writing; readers may coexist.
- Do not delete `case.sqlite-wal` or `case.sqlite-shm`. They are part of the
  live database. Copying only `case.sqlite` while a WAL exists loses committed
  data; use `ghosttrace backup`, which includes committed WAL content.
- If a process crashed, reopen the case. Startup reports interrupted jobs as
  **recoverable** with their last committed locator; nothing is auto-completed.
- A case directory is private to its owner. Opening another user's case fails
  with `permission`; copy it with `ghosttrace backup`/`restore` under the
  owner's account instead of changing ownership of the original.
- The case `locks/` directory holds the application's writer lock. Do not
  remove it manually; a stale lock after a crash is handled on open.

## Schema or migration failure

`schema_incompatible` is fail-closed. It means one of:

- the case was written by a **newer** build (downgrading is not supported);
- a migration file no longer matches its recorded checksum (the repository or
  the case was edited);
- a recorded migration is unknown to this build;
- the required pre-migration backup failed (for example, not enough free
  space), so the schema was not touched.

Use the build that matches the case, or restore a backup into a new directory.
Do not edit `schema_migrations`, `PRAGMA user_version`, or the embedded SQL to
force an open. The pre-migration backup is under the case's `diagnostics/`
directory; keep it until the upgraded case has been verified.

## Times are unresolved, ambiguous, or invalid

GhostTrace never guesses a missing time or zone.

- RFC 3164 syslog has no year and no timezone. Pass `--year` and
  `--timezone`; otherwise the affected events stay `unresolved`. The file mtime
  is not used.
- A DST overlap stays `ambiguous` with both candidates; a DST gap stays
  `unresolved`; a December→January sequence is not silently rolled into the next
  year.
- A malformed timestamp stays `invalid`; a missing one stays `unresolved`. Both
  remain reachable with `timeline --unresolved`, and neither is placed in the
  resolved histogram.
- The display timezone changes presentation only. It never rewrites the
  recorded instant or the raw field.
- Browser and journal epochs are preserved next to the normalized instant;
  monotonic-only journal values never choose a timeline position.

See [timestamps.md](timestamps.md) and
[formats.md](formats.md#time) for the exact rules.

## Signing key or signature failure

- `permission`: the key file must be a regular file, owned by you, mode `0600`
  (not group/other-readable), and not a symlink. Fix the mode/ownership, or
  generate a new key; do not relax the loader.
- `invalid_request`: the passphrase is wrong or shorter than 8 bytes, or the
  prompt is not a terminal. Passphrases are never read from arguments or the
  environment.
- `unsupported_format`: the key is not an encrypted PKCS#8 PEM, uses PBES1 or a
  non-AES-256-CBC cipher, or exceeds the documented KDF bounds. Generate a
  supported key with `ghosttrace key generate`, or re-encrypt an existing
  encrypted PKCS#8 file with `ghosttrace key import --in <old> --out <new>`.
- `integrity_mismatch`: the signature does not cover these exact manifest or
  package bytes. Any whitespace, entry, or digest change invalidates it; do not
  edit the manifest and re-use the old sidecar.
- An existing `<manifest>.sig.json` is never overwritten. Choose another
  `--out` or remove the old sidecar deliberately.
- A valid signature from an unknown key is **accepted** and reported as
  `key_trust:"untrusted"`. Add the fingerprint to your trust file only after
  verifying it out of band; trust is a preference, not proof.
- `verify-package` exit `4` with a missing/unlisted/modified file means the
  package is not intact. Rebuild it from the case; do not "repair" the
  inventory by hand.

Key format and trust-file rules: [formats.md](formats.md#signing-keys-and-detached-signatures).

## Backup or restore failure

- `resource_limit` before a backup means the destination filesystem lacks the
  estimated free space (database + objects + headroom). Free space or choose
  another destination; the command never starts a backup it cannot finish.
- `storage` with a disk I/O error during a snapshot usually means the
  destination filled up. The staging directory is removed; the source case is
  untouched. Retry after freeing space.
- `restore` requires a destination that does not exist. It verifies the
  inventory, stages privately, re-verifies every file, checks SQLite integrity,
  schema version, case id, and object references, and only then renames the new
  case into place. A failure leaves no half-restored case.
- Signing keys and trust lists are intentionally **not** in a backup. Restore
  the case, then re-establish keys/trust separately.

## TUI or terminal problems

- The TUI exits `2` when stdin or stdout is not a terminal, and writes no ANSI
  bytes. Use `timeline`, `search`, `analyze`, or the JSON commands in pipelines.
- On exit, including a panic, the cursor/screen/mode are restored. If a terminal
  is left in raw mode after a hard kill, run `reset` or `stty sane`.
- Evidence text is escaped before display; control and bidi bytes appear as
  visible escapes, and newlines are flattened in table cells. A record cannot
  fabricate rows.
- Mouse input is not required; all views are keyboard reachable. `?` shows the
  full key list.

## Desktop problems

- The desktop needs a display server. On a headless host, use the CLI/TUI or run
  under a virtual display; `ghosttrace-desktop --version` works without a
  display for build identification.
- The default renderer is glow. `--renderer wgpu` selects the optional backend;
  a missing Vulkan loader is a host prerequisite, not a case problem.
- Screenshots for documentation need the `screenshot` cargo feature, the glow
  renderer, and `EFRAME_SCREENSHOT_TO=shot.png`; the app writes one frame and
  exits.
- If a control is unreachable by keyboard, check the accessible name in the
  status/help text and report it with the synthetic sample, not real evidence.

## Large cases, memory, and speed

- The timeline first page is indexed and stays fast at 1M events; the histogram
  deliberately reads the revision and costs roughly 0.4 s per 1M events. It runs
  on a worker, never the render thread.
- Ingest is writer-bound. Measured rates and the narrowed target are in
  [performance.md](performance.md). Do not compare a small warm case with a 1M
  case.
- A backup needs roughly the database size plus object bytes plus headroom;
  `/tmp` on a RAM-backed filesystem counts against RAM.
- The entity build is capped at 200,000 events and relationships are bounded by
  bucket/pair/edge limits. Truncation and skipped buckets are reported, never
  hidden. A large shared basename or IP bucket can legitimately produce no
  edges.

## Reporting a problem

Use the synthetic samples in [`samples/`](../samples/README.md) or the tracked
fixtures to reproduce. Include the command, the stable error code, the tool
version (`--version`), `sqlite-info` when storage is involved, and the relevant
log lines **after** checking that they contain no evidence, paths, URLs, or case
notes. Security issues go through [SECURITY.md](../SECURITY.md), never a public
issue with real evidence.
