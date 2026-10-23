# ADR 0001: Native Rust desktop UI (egui/eframe) with glow as the default renderer

Date: 2026-10-23
Status: Accepted
Plan reference: Section 3 (architecture options), Section 17 P0.1

## Context

The project owner requires a native Rust desktop GUI. Section 3 evaluated three
options: egui/eframe native desktop (selected), iced (reserve alternative), and
a Rust web UI in a webview (rejected). P0.1 must prove the selected stack builds
and behaves on an actual target machine before any forensic feature is claimed.

A second decision P0.1 must make: egui 0.37 can compile the `glow` (OpenGL) and
`wgpu` (Vulkan) backends simultaneously and pick one at runtime via
`NativeOptions::renderer`, so the default must be chosen from measured evidence.

## Decision

1. Use egui/eframe 0.37.0 for the desktop UI. Reject iced for 1.0 (its stable
   accessibility integration was unresolved in the plan's research) and reject a
   webview UI (violates the native-GUI requirement).
2. Ship `glow` as the default renderer. `wgpu` remains available behind the
   `ghosttrace-desktop` `wgpu` cargo feature for evaluation on Windows/macOS
   targets, where the choice is re-decided with driver evidence.
3. Keep egui 0.37's API shape in mind for all later GUI work: `eframe::App`
   now requires `fn ui(&mut egui::Ui, &mut eframe::Frame)`; per-frame non-UI
   work belongs in `fn logic(&mut egui::Context, &mut eframe::Frame)`; panels
   are `egui::Panel::left/top/bottom(...)` shown into the root `Ui`.

## Evidence (2026-10-23, x86_64 Linux, this host)

Toolchain 1.99.1 resolved the full candidate set; edition 2024.

Renderer measurements (background job streaming 200 records while frames were
timed; display capped at ~40 fps under this X server's compositing):

| Build | Release binary size | Job frames | avg frame | p95 frame | max frame |
|---|---|---|---|---|---|
| glow only | 23.7 MB | 206 | 24.36 ms | 27.11 ms | 37.95 ms |
| wgpu only | 30.9 MB | 198 | 25.26 ms | 29.30 ms | 110.57 ms (first frame) |
| glow + wgpu | 31.7 MB | — | — | — | — |

- Frame intervals are compositor/vsync-capped (~25 ms), not blocked by job
  work: the job streamed 153–191 records through a bounded 64-message queue
  while frames continued. First-frame spikes are larger on wgpu (shader/pipeline
  warm-up). No UI-thread stall beyond the first frame was observed.
- Both backends also ran on the host's native Wayland session (wgpu: 154 frames,
  avg 25.88 ms) and under Xwayland.
- Vulkan (`libvulkan.so.1`) and Mesa GL are both present on this host; glow
  additionally has a software fallback path (llvmpipe) which wgpu does not
  guarantee on every Linux target.

## Consequences

- Desktop builds must enable exactly one of `glow`/`wgpu` (or both) as cargo
  features; the crate's `default = ["glow"]`.
- Immediate-mode constraint stays: no database or evidence I/O inside `ui`;
  per-frame logic goes in `logic`, async work through Tokio workers and bounded
  channels (already demonstrated in the P0.1 pilot).
- Accessibility runs through AccessKit (verified compiled with the AT-SPI Unix
  adapter). Live screen-reader verification (NVDA/VoiceOver/Orca) remains a
  release-target gate; see `docs/releases.md` for the host-environment gaps
  recorded during P0.1.
- Re-run the renderer comparison when Windows/macOS targets are verified
  (P6/P10); if wgpu is better there, add a per-platform default rather than
  changing the Linux default without new measurements.
