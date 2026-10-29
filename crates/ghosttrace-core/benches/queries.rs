//! P10.2 microbenchmarks for the hot read paths.
//!
//! The end-to-end numbers (capture, ingest, backup, RSS) come from
//! `xtask scale run`. These benchmarks isolate the query shapes a render pass
//! calls, on a small deterministic case built once per process. They are not a
//! substitute for the scale run: they catch accidental per-query regressions
//! (a lost index, a widened scan) quickly, while the scale run catches
//! whole-system regressions with real ingest and writes.

use std::io::Write;
use std::sync::atomic::AtomicBool;

use criterion::{Criterion, criterion_group, criterion_main};
use ghosttrace_core::capture::copy::{AcquisitionOptions, CopyProgress, run_acquisition};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::ingest::{ImportRequest, LogFormat, run_import};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};

const EVENTS: u64 = 20_000;

struct Fixture {
    session: CaseSession,
    revision: String,
    first_event: String,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    std::fs::create_dir_all(&source).expect("source");
    let mut events = std::fs::File::create(source.join("events.jsonl")).expect("events file");
    for index in 0..EVENTS {
        let needle = if index % 1_000 == 0 { " needle" } else { "" };
        writeln!(
            events,
            "{{\"ts\":\"2026-01-01T00:00:{:02}Z\",\"seq\":{index},\
             \"host\":\"host-{:02}\",\"msg\":\"event {index}{needle}\"}}",
            index % 60,
            index % 100
        )
        .expect("write event");
    }
    events.flush().expect("flush");

    let session = CaseSession::create(
        dir.path(),
        "bench",
        CreateCaseSpec {
            label: "bench".into(),
            display_timezone: "UTC".into(),
            description: "criterion fixture".into(),
        },
    )
    .expect("create case");
    let root = session.layout().root().to_path_buf();
    let spec = CaptureSpec {
        roots: vec![CaptureRoot {
            native: NativePath::unix(source.as_os_str().as_encoded_bytes().to_vec()),
            label: "source".into(),
        }],
        follow_symlinks: false,
        max_depth: 2,
        max_entries: 8,
        max_file_bytes: 1 << 30,
        case_directory: root.clone(),
    };
    let options = AcquisitionOptions::new(AcquisitionMethod::ProtectedCopy, "bench", &spec);
    run_acquisition(&session, &spec, &options, &CopyProgress::new()).expect("capture");

    let reader = session.reader().expect("reader");
    let cancelled = AtomicBool::new(false);
    let mut request = ImportRequest::new(&cancelled);
    request.path = Some("events.jsonl".into());
    request.format = Some(LogFormat::Jsonl);
    request.jsonl.message_field = Some("msg".into());
    run_import(&reader, session.writer(), &root, &request).expect("import");

    let revision = session
        .reader()
        .expect("reader")
        .latest_revision(None)
        .expect("revision")
        .expect("revision exists");
    let query = EventQuery {
        revision: revision.clone(),
        limit: 200,
        ..EventQuery::default()
    };
    let first_event = session
        .query_events(&query)
        .expect("first page")
        .rows
        .first()
        .expect("one row")
        .event_id
        .clone();
    Fixture {
        session,
        revision,
        first_event,
        _dir: dir,
    }
}

fn query_benchmarks(criterion: &mut Criterion) {
    let fixture = fixture();
    let query = EventQuery {
        revision: fixture.revision.clone(),
        limit: 200,
        ..EventQuery::default()
    };

    criterion.bench_function("timeline_first_page_200", |bencher| {
        bencher.iter(|| fixture.session.query_events(&query).expect("page"))
    });
    criterion.bench_function("timeline_histogram_24", |bencher| {
        bencher.iter(|| {
            fixture
                .session
                .event_histogram(&query, None, 24)
                .expect("histogram")
        })
    });
    criterion.bench_function("timeline_search_phrase", |bencher| {
        bencher.iter(|| {
            fixture
                .session
                .search_events(&query, "\"needle\"")
                .expect("search")
        })
    });
    criterion.bench_function("event_detail", |bencher| {
        bencher.iter(|| {
            fixture
                .session
                .event_detail(&fixture.revision, &fixture.first_event)
                .expect("detail")
        })
    });
}

criterion_group!(benches, query_benchmarks);
criterion_main!(benches);
