# Performance

Measured baselines for the targets in plan Section 14. Every number names the
corpus, build, and host that produced it. These are observations on one machine,
not universal throughput promises; the point is to catch a regression and to
keep advertised targets honest.

## Reference profile (this run)

| Item | Value |
|---|---|
| Host | Intel Core i5-8500, 6 logical cores, 23 GiB RAM |
| OS / kernel | Arch Linux, `7.2.9-arch1-1` |
| Filesystem | `/tmp` is tmpfs (RAM-backed); case and corpus live there |
| SQLite | bundled `rusqlite`, SQLite 3.53.2 |
| Build | `--release` (no debug assertions) |
| Tool version | `0.1.0-alpha.1` |
| Corpus seed | `1` |
| 1M corpus | 1,000,000 JSONL events, 200 small files, no large file, 197,297,642 bytes, SHA-256 `fb2417c5a455e82b7b68d069d47b5fdad22e8d8406ae5346614bec1d7e045249` |
| Cache state | warm OS page cache; “cold” below means the first query after opening a fresh reader, not a dropped kernel cache |

The plan's reference profile is 8 logical cores and 16 GiB RAM; this host has
6 cores and 23 GiB. Treat absolute numbers as this host's, and compare future
runs on the same host.

## Targets and achieved

| Metric | Target (plan Section 14) | Achieved | Verdict |
|---|---|---|---|
| Timeline first page, warm p95 | ≤ 200 ms | 0.71 ms p95, 0.72 ms max (200 rows) | Met |
| Timeline first page, cold | ≤ 1 s | 0.68 ms | Met |
| JSONL ingest, writes/indexing included | ≥ 25,000 events/s | 5,150 events/s (194.2 s for 1M) | **Narrowed** (see below) |
| Core RSS on 1M events | ≤ 512 MiB | 69.5 MiB (71,164 KiB) | Met |
| Bounded relationships, warm p95 | ≤ 300 ms | 0.69 ms p95 (1M, 0 rows); 1.38 ms p95 (20k, 80 rows) | Met on populated graphs |
| GUI frame while rendering a full timeline | most ≤ 16.7 ms, none > 100 ms | p50 0.90 ms, p95 0.92 ms, max 0.96 ms | Met |
| Cancellation acknowledgment | ≤ 250 ms, work stops ≤ 2 s | structural tests; see below | Met structurally |
| Capture hashing | report MiB/s and files/s, no universal promise | 212.9 MiB/s, 227 files/s (1M corpus); 184.6 MiB/s, 34.5 files/s (large-file corpus); 52.2 MiB/s, 524 files/s (100k-file ext4, combined run); 38.3 MiB/s, 375 files/s (10-GiB ext4, capture-only) | Reported |

The ingest target is the only unmet number. It is narrowed in this document
rather than quietly dropped: the advertised figure for this profile is
**5,000 normalized events/s including writes and indexing**, with 12,000/s on
a warm 20,000-event case. The gap and the remaining bottleneck are described
below.

## Capture and ingest

`xtask scale run` times a protected copy of the whole corpus (hashing and
publication included) and then a JSONL import with all SQLite writes and index
maintenance included.

Measured on the 1M corpus:

| Step | Result |
|---|---|
| Capture | 201 files, 197,348,842 bytes in 0.884 s (212.9 MiB/s, 227 files/s) |
| Ingest | 1,000,000 events in 194.164 s (5,150 events/s) |
| Backup | 1,980,294,779 bytes in 51.0 s; verification 11.4 s; 31 files verified |
| Peak RSS | 71,164 KiB |

Capture on the large-file corpus (10 × 64 MiB plus the small files): 12 files,
67,301,154 bytes in 0.348 s (184.6 MiB/s, 34.5 files/s). File rate falls with
file size because hashing and copying dominate; the two rates are reported
separately, as the plan requires.

### 10-GiB / 100,000-file corpus (2026-10-30, ext4)

The plan asks for a 10-GiB / 100,000-file capture corpus. It was run in two
parts, both release builds of `1.0.0-rc.1` on this host with the case and
corpus on `/var/tmp` — ext4 on the same SSD — not tmpfs. Cache state: the
corpus was written immediately before capture, so the page cache was partially
warm; both runs were the only heavy work on the machine.

| Run | Corpus | Result |
|---|---|---|
| Combined (`xtask scale run --skip-graph`, seed 1) | 1M JSONL events + 100,000 × 102,400-byte files | capture 10,437,297,642 bytes (9.72 GiB), 100,001 files, 190.7 s = 52.2 MiB/s, 524 files/s; ingest 1,000,000 events in 495.4 s = 2,019 events/s; backup 2,072,969,378 bytes in 90.4 s + 10.1 s verification (31 files); peak RSS 439 MiB |
| Capture-only (`ghosttrace scan`, seed 1) | 100,000 × 107,374-byte files, no events | 10,737,400,000 bytes (10.0 GiB), 100,001 files, 267.0 s = 38.3 MiB/s, 375 files/s, 0 coverage gaps, state `completed`; peak RSS 441 MiB |

The combined run captured 9.72 GiB, not a full 10 GiB; the capture-only run
closes that wording at 10,737,400,000 bytes. Honest findings:

1. **The ingest target is filesystem-dependent.** The 5,150 events/s figure
   above was measured with the case on tmpfs, where a `synchronous=FULL`
   commit costs nothing. The same build importing the same 1M events onto
   ext4 measures **2,019 events/s**: durable commits are the price in the
   synthetic-corpus path, exactly as the optimization narrative says, and the
   disk is where that price is paid. The 5,000 events/s advertised target
   holds for the RAM-backed profile in the table above; on this host's SSD the
   durable-write figure is about 2,000 events/s. Query timings shift the same
   way — first page p95 3.64 ms (vs 0.71 ms), histogram p95 602 ms (vs 376 ms)
   — but stay inside their targets.
2. **The 100,000-file corpora measure per-file cost, and dedup means published
   bytes ≠ captured bytes.** Every file is read, hashed, and staged before
   publication, then deduplicated by content digest; the synthetic files vary
   only in their first byte, so the combined run's full 9.72 GiB pass
   published 28 objects totalling 191 MiB. The reported rates are therefore copy+hash+dedup
   throughput over the full corpus, not unique-storage throughput, and the
   38–52 MiB/s byte rates on 100 KiB files are dominated by per-file staging
   plus hashing rather than by raw copy. No correctness gap was introduced:
   coverage reported 100,001 captured, 0 gaps, `completed`.
3. **Peak RSS triples with 100,000 files and stays under the target.** The
   capture-only run — which ingests nothing — peaked at 441 MiB (451,676 KiB),
   and the combined run at 439 MiB, against 69.5 MiB for the tmpfs
   1M-ingest-only run. Both are under the 512 MiB target, but the headroom is
   smaller than the 1M-ingest figure alone suggests; the cost belongs to the
   100,000-file capture state in this build, not to ingest.

The import is writer-bound, not parser-bound. Three measured fixes were needed
to reach the published number:

1. **Progress upserts no longer assign the primary key.** Assigning
   `parse_runs.id = excluded.id` made SQLite treat every batch-progress write as
   a parent-key update and check the child foreign keys, which scanned the
   growing `events` table. At 100k events a single progress write cost 27 ms;
   after the fix it cost 59 µs.
2. **Batches are packed into multi-row statements.** One INSERT per event meant
   one statement (and one trigger statement journal) per row. Grouping the
   batch by shape and binding 250 rows per statement removed most of that fixed
   cost.
3. **The WAL is checkpointed less often.** Batches crossed the default
   1,000-page threshold, so commits paid for a 4 MiB checkpoint repeatedly. The
   writer now bounds the WAL at 10,000 pages (40 MiB).

The remaining cost is per-row SQLite work: each event writes three rows
(`events`, `event_times`, `raw_observations`), the `events` table maintains five
indexes, the FTS5 trigger indexes summary/kind/host, and commits use
`synchronous=FULL`. Reaching 25,000/s on this schema would require a bulk-load
path that defers or drops derived indexes and rebuilds them afterwards. That
changes crash-consistency semantics, so it was not done in P10.2; the target is
narrowed instead. Re-measure before raising it.

The 20,000-event corpus imports at 12,445 events/s; the rate falls with case
size as the B-trees and FTS index grow. Do not compare that number with the 1M
figure directly.

While measuring backups, the entity build was found to hold one read cursor
across the whole 200,000-event scan while writing links. In WAL mode that pinned
the snapshot and grew the WAL to 3.6 GiB, which then made the backup run out of
space. The scan now reads 10,000-event chunks, closes the cursor, and flushes
before the next chunk; the backup also checkpoints the WAL best-effort before
snapshotting. The 1M run now ends with a 0-byte WAL.

## Graph and relationships

On the 1M corpus the entity build scans the 200,000-event cap (reported as
`truncated: true`), producing 50,641 entities and 600,000 links in 22.9 s.
Default correlation then derives 0 edges and reports `buckets_skipped: 500`:
the synthetic corpus reuses each basename and IP across more than the
32-entity bucket bound, so every candidate bucket is skipped by design. The
relationship query still returns in 0.69 ms p95, but on an empty result.

The 20,000-event corpus stays under the entity cap and produces 32,829
entities, 60,000 links, and 5,000 derived edges (capped by `max_edges`, reported
as `truncated: true`), with 150 buckets skipped. The bounded-neighborhood query
returns 80 rows at 1.38 ms p95. Use that run when measuring populated
relationship rendering; use the 1M run to demonstrate the bounds.

## Query plans

The timeline query uses the recorded keyset index; it does not scan the
revision. On the generated 1M case:

```text
EXPLAIN QUERY PLAN
SELECT ... FROM events
WHERE revision = ? AND chosen_seconds IS NOT NULL ... ORDER BY chosen_seconds, chosen_nanos, id LIMIT 201;

|--SEARCH events USING INDEX events_by_time_keyset (revision=? AND chosen_seconds>?)
`--CORRELATED SCALAR SUBQUERY 1
   `--SEARCH p USING INDEX sqlite_autoindex_parse_runs_1 (id=?)
```

The correlated `parse_runs` lookup only runs when a source filter is set; the
ordinary timeline passes `NULL` and the index does the work. No query plan in
the measured shapes showed a full scan of `events`.

Measured query shapes on the 1M case (20 iterations, warm):

| Query | p50 | p95 | Rows |
|---|---|---|---|
| First page | 0.68 ms | 0.71 ms | 200 |
| Second page | 0.68 ms | 0.73 ms | 200 |
| Histogram (24 bins) | 371.4 ms | 376.3 ms | 1,000,000 |
| Event detail | 0.48 ms | 0.49 ms | 1 |
| Phrase search | 1.09 ms | 1.17 ms | 100 |
| Relationships | 0.44 ms | 0.69 ms | 0 |

The histogram deliberately reads every event in the revision; ~0.38 s per
1M events is the accepted cost, and the desktop worker keeps it off the render
thread.

## GUI responsiveness

The render pass never touches SQLite: it reads `AppState` and emits
`QueryRequest`s that a worker consumes through `take_queries` (see
`docs/architecture.md`), so frame cost is layout and drawing. `gui_frame_budget`
renders the timeline with the page cache at its 1,000-row bound and a 60-bin
histogram through the real widget tree; it is ignored by default because
absolute frame times are host-dependent:

```bash
cargo test --release -p ghosttrace-desktop --test gui_frame_budget -- --ignored --nocapture
```

Measured: p50 0.90 ms, p95 0.92 ms, max 0.96 ms (1,000 rows, 60 bins). The
16.7 ms budget is met with a wide margin on this host. The test is a regression
canary, not a CI gate.

## Cancellation

Cancellation is a shared atomic: `CommandBus::cancel` stores the flag
synchronously, so acknowledgment is immediate (no queue round-trip). The work
stops at the next chunk or batch boundary; `desktop_jobs` asserts that a cancel
arriving before the worker registers its handle is still honored and that a
cancelled copy reports `cancelled` rather than a success. Blocked OS I/O can
outlast the 2-second cooperative target and is disclosed rather than papered
over.

## Limitations

- One host, two filesystems. `/tmp` is RAM-backed here, so storage latency is
  better than a spinning disk or a network share; `xtask scale run` was also
  re-run with the case on ext4 (100,000-file section), which is the honest
  number for durable writes.
- The 1M corpus is synthetic and benign: short ASCII messages, no hostile
  parser payloads, no personal data.
- “Cold” is a fresh reader over a warm OS cache, not a dropped page cache.
- The plan's 10 GiB / 100,000-file capture corpus has been run (100,000-file
  section above). It is synthetic: files differ only in their first byte, so
  deduplication publishes 28 objects from 9.72 GiB of copied+hashed bytes.
  Windows and macOS were still not measured; only Linux x86_64 is a tested
  target in this revision.
- The 1M corpus does not exercise populated relationship queries under the
  default bucket bounds; the 20k run does. Both are reported.
- Windows and macOS were not measured; only Linux x86_64 is a tested target in
  this revision.
- Benchmarks are not a CI gate. Criterion microbenchmarks catch query-shape
  regressions; `xtask scale run` is the release-time end-to-end check.

## Microbenchmarks

`cargo bench -p ghosttrace-core --bench queries` builds a 20,000-event case and
measures first page, histogram, phrase search, and event detail. On this host:

| Benchmark | Estimate |
|---|---|
| `timeline_first_page_200` | 1.42 ms |
| `timeline_histogram_24` | 9.34 ms |
| `timeline_search_phrase` | 762 µs |
| `event_detail` | 574 µs |

These isolate query shapes; the end-to-end numbers above include storage and
real ingest. A ≥20% move in either set should be re-measured before a release
and explained in the changelog.
