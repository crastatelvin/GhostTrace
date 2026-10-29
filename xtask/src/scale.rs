//! `xtask scale` — reproducible corpora and end-to-end measurements (plan
//! P10.2).
//!
//! `generate` writes a deterministic JSONL corpus plus optional small files and
//! one large file, and records the exact counts and SHA-256 digests in
//! `corpus.json`. `run` re-verifies that manifest, creates a case, times
//! capture and ingest with writes included, then times cold/warm first-page,
//! keyset, histogram, detail, search, entity build, bounded relationships, and
//! backup. Every number is printed with the environment and corpus identity so
//! a later run can be compared honestly.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use ghosttrace_core::analysis::correlate::{CorrelateConfig, RelationshipQuery};
use ghosttrace_core::analysis::entities::build_entities;
use ghosttrace_core::capture::copy::{AcquisitionOptions, CopyProgress, run_acquisition};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::ingest::{ImportRequest, LogFormat, run_import};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::backup::backup_case;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Subcommand)]
pub enum ScaleCommand {
    /// Generate a deterministic corpus and its count/digest manifest.
    Generate(GenerateArgs),
    /// Generate (or reuse) a corpus, build a case, and measure it.
    Run(RunArgs),
}

#[derive(Args, Clone)]
pub struct GenerateArgs {
    /// Directory that receives `corpus/` and `corpus.json`.
    #[arg(long)]
    pub output: PathBuf,
    /// Number of JSONL event records.
    #[arg(long, default_value_t = 100_000)]
    pub events: u64,
    /// Number of small files in `corpus/files/`.
    #[arg(long, default_value_t = 100)]
    pub files: u64,
    /// Bytes for each small file (default 256).
    #[arg(long, default_value_t = 256)]
    pub file_bytes: u64,
    /// Bytes for one `corpus/large.bin` file (0 disables it).
    #[arg(long, default_value_t = 0)]
    pub large_file_bytes: u64,
    /// Deterministic seed.
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
}

#[derive(Args)]
pub struct RunArgs {
    /// Directory that receives `corpus/`, `corpus.json`, the case, and backups.
    #[arg(long)]
    pub output: PathBuf,
    /// Number of JSONL event records.
    #[arg(long, default_value_t = 100_000)]
    pub events: u64,
    /// Number of small files in `corpus/files/`.
    #[arg(long, default_value_t = 100)]
    pub files: u64,
    /// Bytes for each small file (default 256).
    #[arg(long, default_value_t = 256)]
    pub file_bytes: u64,
    /// Bytes for one `corpus/large.bin` file (0 disables it).
    #[arg(long, default_value_t = 0)]
    pub large_file_bytes: u64,
    /// Deterministic seed.
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// Warm iterations for each query shape.
    #[arg(long, default_value_t = 20)]
    pub iterations: usize,
    /// Skip entity build and relationship timing (cheap runs).
    #[arg(long)]
    pub skip_graph: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CorpusManifest {
    format: String,
    seed: u64,
    events: u64,
    files: u64,
    #[serde(default = "default_file_bytes")]
    file_bytes: u64,
    large_file_bytes: u64,
    event_bytes: u64,
    event_sha256: String,
    large_sha256: Option<String>,
}

const CORPUS_FORMAT: &str = "ghosttrace-scale-corpus/1";

fn default_file_bytes() -> u64 {
    256
}
const NEEDLE_EVERY: u64 = 10_000;

pub fn run(command: ScaleCommand) -> Result<(), String> {
    match command {
        ScaleCommand::Generate(args) => {
            let manifest = generate(&args)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        ScaleCommand::Run(args) => run_case(args),
    }
}

fn generate(args: &GenerateArgs) -> Result<CorpusManifest, String> {
    let corpus = args.output.join("corpus");
    std::fs::create_dir_all(corpus.join("files"))
        .map_err(|error| format!("corpus dir: {error}"))?;
    let (event_bytes, event_sha256) =
        write_events(&corpus.join("events.jsonl"), args.events, args.seed)?;
    let mut rng = Rng(args.seed ^ 0x5DEECE66D);
    let mut block = vec![0_u8; 4096];
    for byte in &mut block {
        *byte = b'a' + (rng.next() % 26) as u8;
    }
    let mut bytes = Vec::with_capacity(args.file_bytes as usize);
    while bytes.len() < args.file_bytes as usize {
        let take = (args.file_bytes as usize - bytes.len()).min(block.len());
        bytes.extend_from_slice(&block[..take]);
    }
    for index in 0..args.files {
        // Vary the first byte so files are not hardlink/duplicate candidates.
        let mut content = bytes.clone();
        if let Some(first) = content.first_mut() {
            *first = b'a' + (index % 26) as u8;
        }
        std::fs::write(
            corpus.join("files").join(format!("file-{index:05}.txt")),
            content,
        )
        .map_err(|error| format!("corpus file: {error}"))?;
    }
    let large_sha256 = if args.large_file_bytes > 0 {
        Some(write_large(
            &corpus.join("large.bin"),
            args.large_file_bytes,
        )?)
    } else {
        None
    };
    let manifest = CorpusManifest {
        format: CORPUS_FORMAT.into(),
        seed: args.seed,
        events: args.events,
        files: args.files,
        file_bytes: args.file_bytes,
        large_file_bytes: args.large_file_bytes,
        event_bytes,
        event_sha256,
        large_sha256,
    };
    let text = serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;
    std::fs::write(args.output.join("corpus.json"), format!("{text}\n"))
        .map_err(|error| format!("corpus manifest: {error}"))?;
    Ok(manifest)
}

fn write_events(path: &Path, events: u64, seed: u64) -> Result<(u64, String), String> {
    let file = File::create(path).map_err(|error| format!("events file: {error}"))?;
    let mut writer = BufWriter::new(file);
    let mut hasher = Sha256::new();
    let mut rng = Rng(seed);
    let base = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("fixed timestamp")
        .timestamp();
    let mut bytes = 0_u64;
    for index in 0..events {
        let host = rng.next() % 100;
        let user = rng.next() % 50;
        let action = match rng.next() % 4 {
            0 => "start",
            1 => "stop",
            2 => "open",
            _ => "close",
        };
        let seconds = base + (index % 31_536_000) as i64;
        let time = chrono::DateTime::from_timestamp(seconds, 0).expect("timestamp range");
        let needle = if index % NEEDLE_EVERY == 0 {
            " needle-rare"
        } else {
            ""
        };
        // Shared IPs and basenames across hosts give the correlation pass real
        // candidate edges to bound; they are synthetic and never a finding.
        let ip = format!("10.0.{}.{}", (index / 100) % 256, index % 200);
        let path = format!(
            "C:\\\\Users\\\\user-{user:02}\\\\file-{:03}.txt",
            (index / 50) % 500
        );
        let line = format!(
            "{{\"ts\":\"{}\",\"seq\":{index},\"host\":\"host-{host:02}\",\
             \"user\":\"user-{user:02}\",\"ip\":\"{ip}\",\"path\":\"{path}\",\
             \"level\":\"info\",\
             \"msg\":\"event {index} on host-{host:02} action {action}{needle}\"}}\n",
            time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
        writer
            .write_all(line.as_bytes())
            .map_err(|error| format!("events write: {error}"))?;
        hasher.update(line.as_bytes());
        bytes += line.len() as u64;
    }
    writer
        .flush()
        .map_err(|error| format!("events flush: {error}"))?;
    Ok((bytes, hex(&hasher.finalize())))
}

fn write_large(path: &Path, size: u64) -> Result<String, String> {
    let file = File::create(path).map_err(|error| format!("large file: {error}"))?;
    let mut writer = BufWriter::new(file);
    let mut hasher = Sha256::new();
    let block = [0xA5_u8; 64 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let take = remaining.min(block.len() as u64) as usize;
        writer
            .write_all(&block[..take])
            .map_err(|error| format!("large write: {error}"))?;
        hasher.update(&block[..take]);
        remaining -= take as u64;
    }
    writer
        .flush()
        .map_err(|error| format!("large flush: {error}"))?;
    Ok(hex(&hasher.finalize()))
}

fn run_case(args: RunArgs) -> Result<(), String> {
    std::fs::create_dir_all(&args.output).map_err(|error| format!("output: {error}"))?;
    let corpus = args.output.join("corpus");
    let manifest_path = args.output.join("corpus.json");
    let manifest = if manifest_path.is_file() {
        let text = std::fs::read_to_string(&manifest_path)
            .map_err(|error| format!("corpus manifest: {error}"))?;
        let manifest: CorpusManifest =
            serde_json::from_str(&text).map_err(|error| format!("corpus manifest: {error}"))?;
        if manifest.events != args.events
            || manifest.seed != args.seed
            || manifest.files != args.files
            || manifest.file_bytes != args.file_bytes
            || manifest.large_file_bytes != args.large_file_bytes
        {
            return Err(
                "the existing corpus.json does not match the requested size/seed; use a new --output"
                    .into(),
            );
        }
        manifest
    } else {
        generate(&GenerateArgs {
            output: args.output.clone(),
            events: args.events,
            files: args.files,
            file_bytes: args.file_bytes,
            large_file_bytes: args.large_file_bytes,
            seed: args.seed,
        })?
    };
    verify_corpus(&corpus, &manifest)?;

    let case_root = args.output.join("scale.ghosttrace-case");
    if case_root.exists() {
        return Err(format!(
            "{} already exists; use a new --output",
            case_root.display()
        ));
    }
    let session = CaseSession::create(
        &args.output,
        "scale",
        CreateCaseSpec {
            label: "scale".into(),
            display_timezone: "UTC".into(),
            description: "generated P10.2 corpus".into(),
        },
    )
    .map_err(|error| format!("create case: {error}"))?;
    let root = session.layout().root().to_path_buf();

    let spec = CaptureSpec {
        roots: vec![CaptureRoot {
            native: NativePath::unix(corpus.as_os_str().as_encoded_bytes().to_vec()),
            label: "corpus".into(),
        }],
        follow_symlinks: false,
        max_depth: 4,
        max_entries: args.files + 16,
        max_file_bytes: 1 << 40,
        case_directory: root.clone(),
    };
    let options =
        AcquisitionOptions::new(AcquisitionMethod::ProtectedCopy, "generated corpus", &spec);
    let progress = CopyProgress::new();
    let started = Instant::now();
    let capture = run_acquisition(&session, &spec, &options, &progress)
        .map_err(|error| format!("capture: {error}"))?;
    let capture_time = started.elapsed();
    let captured_bytes: u64 = capture.copies.iter().map(|copy| copy.byte_length).sum();
    let captured_files = capture.published_objects();

    let reader = session
        .reader()
        .map_err(|error| format!("reader: {error}"))?;
    let cancelled = AtomicBool::new(false);
    let mut request = ImportRequest::new(&cancelled);
    request.path = Some("events.jsonl".into());
    request.format = Some(LogFormat::Jsonl);
    request.jsonl.message_field = Some("msg".into());
    let started = Instant::now();
    let outcome = run_import(&reader, session.writer(), &root, &request)
        .map_err(|error| format!("import: {error}"))?;
    let ingest_time = started.elapsed();
    if outcome.events != args.events {
        return Err(format!(
            "ingest produced {} events, expected {}",
            outcome.events, args.events
        ));
    }

    let revision = session
        .reader()
        .map_err(|error| format!("reader: {error}"))?
        .latest_revision(None)
        .map_err(|error| format!("revision: {error}"))?
        .ok_or_else(|| "no parse run after import".to_string())?;
    let query = EventQuery {
        revision: revision.clone(),
        limit: 200,
        ..EventQuery::default()
    };

    let cold_started = Instant::now();
    let first = session
        .query_events(&query)
        .map_err(|error| format!("first page: {error}"))?;
    let cold_page = cold_started.elapsed();
    if first.rows.len() != 200 {
        return Err(format!("first page returned {} rows", first.rows.len()));
    }
    let first_page = measure(args.iterations, || {
        session.query_events(&query).map(|page| page.rows.len())
    })?;
    let second_page = measure(args.iterations, || {
        session
            .query_events(&EventQuery {
                after: first.next_cursor.clone(),
                ..query.clone()
            })
            .map(|page| page.rows.len())
    })?;
    let histogram = measure(args.iterations, || {
        session
            .event_histogram(&query, None, 24)
            .map(|histogram| histogram.total as usize)
    })?;
    let detail = measure(args.iterations, || {
        session
            .event_detail(&revision, &first.rows[0].event_id)
            .map(|detail| detail.observations.len())
    })?;
    let search = measure(args.iterations, || {
        session
            .search_events(&query, "\"needle-rare\"")
            .map(|page| page.rows.len())
    })?;
    let search_rows = search.rows;

    let (graph, relationships) = if args.skip_graph {
        (None, None)
    } else {
        let started = Instant::now();
        let built = build_entities(
            session.writer(),
            &session.reader().map_err(|error| error.to_string())?,
            &revision,
        )
        .map_err(|error| format!("entities: {error}"))?;
        let entities_seconds = started.elapsed().as_secs_f64();
        let started = Instant::now();
        let correlated = session
            .correlate(&CorrelateConfig::default())
            .map_err(|error| format!("correlate: {error}"))?;
        let graph = json!({
            "entities_seconds": entities_seconds,
            "events_scanned": built.events,
            "events_without_source": built.events_without_source,
            "entities": built.entities,
            "links": built.links,
            "truncated": built.truncated,
            "correlate_seconds": started.elapsed().as_secs_f64(),
            "derived": correlated.derived,
            "inserted": correlated.inserted,
            "pairs_examined": correlated.pairs_examined,
            "buckets_skipped": correlated.buckets_skipped,
            "unsupported_time": correlated.unsupported_time,
            "correlate_truncated": correlated.truncated,
        });
        let relationships = measure(args.iterations, || {
            session
                .query_relationships(&RelationshipQuery {
                    limit: 80,
                    ..RelationshipQuery::default()
                })
                .map(|page| page.rows.len())
        })?;
        (Some(graph), Some(relationships))
    };

    // Back up a quiescent case: drop the session so its writer checkpoints the
    // WAL and releases the database before the snapshot starts.
    drop(session);
    let backups = args.output.join("backups");
    let started = Instant::now();
    let backup = backup_case(&root, &backups, env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("backup: {error}"))?;
    let backup_time = started.elapsed();
    let started = Instant::now();
    let verified = ghosttrace_core::storage::backup::verify_backup(&backup.directory)
        .map_err(|error| format!("backup verify: {error}"))?;
    let verify_time = started.elapsed();

    let summary = json!({
        "environment": environment(),
        "corpus": manifest,
        "capture": {
            "seconds": capture_time.as_secs_f64(),
            "files": captured_files,
            "bytes": captured_bytes,
            "mib_per_second": rate(captured_bytes, capture_time),
        },
        "ingest": {
            "seconds": ingest_time.as_secs_f64(),
            "events": outcome.events,
            "events_per_second": outcome.events as f64 / ingest_time.as_secs_f64().max(f64::EPSILON),
        },
        "queries": {
            "first_page_cold_ms": ms(cold_page),
            "first_page": first_page,
            "second_page": second_page,
            "histogram": histogram,
            "detail": detail,
            "search": search,
            "search_rows": search_rows,
            "relationships": relationships,
        },
        "graph": graph,
        "backup": {
            "seconds": backup_time.as_secs_f64(),
            "verify_seconds": verify_time.as_secs_f64(),
            "bytes": backup.total_bytes,
            "files": backup.files.len(),
            "verified": verified.files_verified,
        },
        "peak_rss_kib": peak_rss_kib(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn verify_corpus(corpus: &Path, manifest: &CorpusManifest) -> Result<(), String> {
    let digest = hash_file(&corpus.join("events.jsonl"))?;
    if digest != manifest.event_sha256 {
        return Err("corpus events.jsonl does not match corpus.json".into());
    }
    if let Some(expected) = &manifest.large_sha256 {
        let digest = hash_file(&corpus.join("large.bin"))?;
        if &digest != expected {
            return Err("corpus large.bin does not match corpus.json".into());
        }
    }
    let events =
        File::open(corpus.join("events.jsonl")).map_err(|error| format!("corpus read: {error}"))?;
    let lines = std::io::BufReader::new(events).lines().count() as u64;
    if lines != manifest.events {
        return Err(format!(
            "corpus has {lines} event lines, manifest says {}",
            manifest.events
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct Measurement {
    p50_ms: f64,
    p95_ms: f64,
    max_ms: f64,
    rows: usize,
}

fn measure(
    iterations: usize,
    mut action: impl FnMut() -> Result<usize, ghosttrace_core::error::CoreError>,
) -> Result<Measurement, String> {
    let mut samples = Vec::with_capacity(iterations.max(1));
    let mut rows = 0_usize;
    for _ in 0..iterations.max(1) {
        let started = Instant::now();
        rows = action().map_err(|error| format!("measure: {error}"))?;
        samples.push(started.elapsed());
    }
    samples.sort();
    let pick = |fraction: f64| -> f64 {
        let index = ((samples.len() - 1) as f64 * fraction).round() as usize;
        ms(samples[index])
    };
    Ok(Measurement {
        p50_ms: pick(0.50),
        p95_ms: pick(0.95),
        max_ms: ms(*samples.last().expect("sample")),
        rows,
    })
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn rate(bytes: u64, elapsed: Duration) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64().max(f64::EPSILON)
}

fn environment() -> serde_json::Value {
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "debug_assertions": cfg!(debug_assertions),
        "cpu": cpu_model(),
        "sqlite": rusqlite::version(),
        "tool_version": env!("CARGO_PKG_VERSION"),
    })
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("model name"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let value = line.strip_prefix("VmHWM:")?;
        value.split_whitespace().next()?.parse().ok()
    })
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("hash open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|error| format!("hash read: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Deterministic SplitMix64; the corpus never uses OS randomness.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
