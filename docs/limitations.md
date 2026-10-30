# Limitations

This page collects the claims GhostTrace deliberately does **not** make. Each
one is enforced by a test, a bound, or a fail-closed check somewhere in the
codebase; none is a promise to add later.

## Acquisition

- GhostTrace copies logical files. It does not acquire raw disk images, memory,
  firmware, or hardware state, and it does not provide a write blocker. Use a
  protected copy or a validated write-blocking process when that matters.
- Symbolic links are recorded, not followed. Sockets, devices, and FIFOs are
  not copied. Hardlink aliases are stored once and reported.
- Reading a source can update access-time metadata. That effect is disclosed;
  it is not asserted absent.
- A live capture is best effort. Permissions, open handles, changing files, and
  files that vanish mid-read become coverage gaps. A partial capture is valid
  only for the captured scope.
- A missing path in a later partial capture is **not** evidence of deletion.
  The diff reports `unknown`, never `not_present_in_captured_scope`, when the
  later scope has a gap at that path.

## Formats

Supported, with tested mappings:

| Input | Adapter |
|---|---|
| JSONL | fixed field names and five time encodings; no expressions or regex |
| Syslog RFC 5424 / RFC 3164 | raw header fields; RFC 3164 needs `--year` and `--timezone` |
| systemd journal | `journalctl -o export` only |
| Chromium / Firefox history | captured main SQLite database plus `-wal`/`-shm` sidecars |
| Windows EVTX | the provider/event mapping table in [formats.md](formats.md); unreadable chunks are reported |

Deliberately unsupported: native `.journal` files, Windows registry, MFT,
prefetch, shellbags, raw disk/memory, browser cache content, executing or
importing downloaded files, regex/script field mappings, virtual tables or
views in browser databases, provider message DLL rendering, DTD/entity
resolution, and carving deleted records from unallocated space. See
[formats.md](formats.md#not-supported-deliberate) for the full list and reasons.

Adding a format requires a bounded parser, fixtures, a test, documentation, and
a mapping table version. A parser failure is reported as a diagnostic or a
failed/partial run, never as a silent empty success.

## Analysis and attribution

- There are five compiled rules, no script engine, and no arbitrary SQL.
  Rule parameters change thresholds and windows, never logic.
- There is **no maliciousness score or percentage** anywhere. A finding carries
  a fixed severity band, its exact predicates, supporting event ids, a
  rationale, and named alternatives.
- An IP or basename match is a candidate, not an identity. Equal digests mean
  equal bytes, not a proven copy, move, or common author.
- Correlation is bounded by bucket size, pair budget, and edge budget. Skipped
  buckets and truncation are counted and displayed. A large shared basename or
  IP bucket can legitimately produce no edges.
- GhostTrace does not attribute activity to a person, organization, or malware
  family, and it does not reorder events across hosts or boots.

## Custody and signatures

- A manifest digest proves the stored bytes match the recorded bytes. It does
  not prove that the source was truthful or that collection was complete.
- A signature proves that a specific Ed25519 key signed the exact manifest or
  package bytes. It does not prove when collection happened, who controlled the
  host, or that custody was legally sufficient.
- Key trust is an explicit user-maintained fingerprint list outside the case. A
  valid signature from an unknown key is accepted and labelled `untrusted`;
  trust is a preference, not evidence.
- Keys are local and free. Optional paid platform signing (Apple notarization,
  commercial Windows signing) affects installer trust only. No feature is
  withheld for payment, and no subscription is required.
- Signing cannot protect against a compromised host, swap, crash dumps, or a
  stolen passphrase. Zeroization covers the in-memory key and passphrase
  buffers only.

## Platform and accessibility

- Linux x86_64 is the only platform with build-and-run evidence in this
  revision. Windows and macOS code paths exist but are unverified release-gate
  items; a successful compile is not support.
- The desktop uses a native egui/eframe shell with keyboard-reachable controls
  and accessible names. Automated `egui_kittest` tests run, but live NVDA,
  VoiceOver, and Orca sessions and Windows Terminal/macOS terminal smoke checks
  remain open gate items. Do not claim screen-reader conformance until those
  runs are recorded.
- `wgpu` rendering was verified once on the recording host under a software
  Vulkan ICD (Xvfb + lavapipe), not on hardware drivers, and not on every
  host; glow remains the default.

## Performance

Measured numbers are for one host, one filesystem, and one synthetic corpus.
They are regression baselines, not universal throughput promises. The 1M-event
ingest target is narrowed to the measured value in
[performance.md](performance.md); the histogram deliberately scans the
revision, and the entity build is capped at 200,000 events. The
10 GiB / 100,000-file capture corpus was run on the recording host (ext4;
its synthetic files deduplicate, so it measures copy+hash+coverage cost, not
10 GiB of unique storage); Windows/macOS measurements were not run on the
recording host.

## Network and privacy

- No telemetry, uploads, automatic updates, URL fetching from artifacts, or
  background network listeners. The optional read-only localhost API is a
  post-1.0 task and is absent unless explicitly enabled and bound to loopback.
- Diagnostics and reports do not include raw evidence, artifact paths, URLs, or
  case notes unless you explicitly export them after preview. Redaction is
  available for reports and packages, and its ledger records field names and
  counts only.
