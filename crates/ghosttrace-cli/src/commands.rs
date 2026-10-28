//! CLI commands (plan Sections 9, 17/P2.3).
//!
//! Contract: machine-readable JSON on stdout, progress and diagnostics on
//! stderr, and documented exit codes — `0` clean, `1` failed, `2` invalid
//! usage, `3` partial result or coverage omission.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;

use ghosttrace_core::analysis::diff::{DiffQuery, DiffReport, compare_acquisitions};
use ghosttrace_core::analysis::rules::{AnalysisRequest, RuleConfig};
use ghosttrace_core::capture::copy::{
    AcquisitionOptions, CopyProgress, inspect_recovery, run_acquisition,
};
use ghosttrace_core::capture::{CaptureRoot, CaptureSpec};
use ghosttrace_core::domain::case::AcquisitionMethod;
use ghosttrace_core::domain::path::NativePath;
use ghosttrace_core::domain::query::{EventQuery, EventRow, TimeCursor};
use ghosttrace_core::error::CoreError;
use ghosttrace_core::ingest::{
    self, DEFAULT_MAX_RECORD_BYTES, DEFAULT_MAX_RECORDS, ImportRequest, JsonlConfig, LogFormat,
    SyslogConfig, TimeFormat,
};
use ghosttrace_core::integrity::manifest::ManifestV1;
use ghosttrace_core::reports::{self, ReportContext, ReportSelection};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::CASE_DIR_SUFFIX;

use crate::output;

pub const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_PARTIAL: u8 = 3;
pub const EXIT_VERIFY: u8 = 4;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(
    name = "ghosttrace",
    version,
    about = "GhostTrace forensic workbench: local-first, evidence read-only"
)]
pub enum Cli {
    /// Print the linked SQLite/runtime verification report as JSON.
    SqliteInfo,
    /// Case lifecycle commands.
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Capture a source folder into a case (copy + SHA-256 + coverage).
    Scan(ScanArgs),
    /// Report stored acquisitions, coverage, and recovery leftovers.
    Status(StatusArgs),
    /// Query the event timeline with bounded filters and keyset paging.
    #[command(
        long_about = "Query the event timeline with bounded filters and keyset paging.\
\n\nThe resolved view orders by chosen time; events without a resolved time are\
 never mixed in and remain reachable with --unresolved. --last anchors to the\
 newest instant in the case unless --until supplies an explicit upper bound."
    )]
    Timeline(TimelineArgs),
    /// Full-text search over indexed event summary, kind, and host text.
    #[command(
        long_about = "Full-text search over indexed event summary, kind, and host text.\
\n\nThe search grammar is deliberately tiny: bare words, \"quoted phrases\", and a\
 leading `-` to exclude a term. Anything else is rejected with an explanation\
 instead of silently reinterpreted. The expression is passed to FTS5 as a bound\
 parameter; no operator text ever enters SQL. Structured filters and keyset\
 paging are identical to `timeline`. Raw field values that are not summary,\
 kind, or host text are not indexed and stay reachable through `timeline` and\
 the event detail."
    )]
    Search(SearchArgs),
    /// Compare two acquisitions of the same roots.
    #[command(long_about = "Compare two acquisitions of the same roots.\
\n\nAbsence in the later capture means \"not present in the captured scope\",\
 never \"deleted\". A coverage gap at that path makes the result unknown.\
 Equal full hashes at different paths are move candidates: bytes alone never\
 prove a copy or move. Acquisitions with different roots are reported unknown.\
 Timestamp equality never proves unchanged bytes.")]
    Diff(DiffArgs),
    /// Verify a stored acquisition manifest and its captured objects.
    #[command(
        long_about = "Verify a stored acquisition manifest and its captured objects.\
\n\nThe manifest is re-read from disk, duplicate JSON keys are rejected, the\
 format version must match, every referenced path must stay inside the case\
 store, and every stored object is re-hashed. This is an unsigned integrity\
 check: it proves the bytes still match the record, not who produced them.\
 Exit code 4 means the manifest did not verify; 0 means it did."
    )]
    Verify(VerifyArgs),
    /// Export a versioned JSON + self-contained HTML report.
    #[command(long_about = "Export a versioned JSON + self-contained HTML report.\
\n\nThe report describes the recorded case only: coverage gaps, stored object\
 hashes, and the application-clock timeline. The HTML carries no scripts, no\
 links, and no remote resources. Publication is atomic and never overwrites an\
 existing report directory.")]
    Report(ReportArgs),
    /// Import a captured log object through a bounded, versioned adapter.
    #[command(
        long_about = "Import a captured log object through a bounded, versioned adapter.\
\n\nThe adapter reads only the captured case object, detects the format from a\
 bounded signature prefix unless --format declares one, records a versioned\
 parse run with exact locators, and never invents an event type or a time.\
 RFC 3164 has no year and no timezone: provide --year and --timezone, or the\
 affected times stay unresolved. December→January sequences stay ambiguous.\
\n\nExit 0 means every record was parsed cleanly, 3 means diagnostics were\
 recorded (or the run was cancelled), and 1/2 mean the import did not run."
    )]
    Import(ImportArgs),
    /// Evaluate the five compiled rules against a recorded revision.
    #[command(
        long_about = "Evaluate the five compiled rules against one recorded revision.\
\n\nEvery finding names its rule version, the recorded events it used, the exact\
 predicates, the counts behind the decision, and the alternatives that remain\
 plausible. Rules with missing prerequisites report `not_evaluated` with a\
 reason instead of producing a guess. The outside-hours rule stays disabled\
 until --rules supplies an explicit schedule baseline. There is no script\
 engine and no maliciousness score.\n\nExit 0 means the run completed, 3 means\
 a bound truncated the pass, and 2 means the rule parameters were invalid."
    )]
    Analyze(AnalyzeArgs),
    /// Browse the timeline, search, event detail, and findings interactively.
    #[command(
        long_about = "Browse the timeline, search, event detail, and findings interactively.\n\nThe TUI reads through the same query and analysis contracts as `timeline`, `search`, and `analyze`, so a selection yields the same recorded event and detail. It needs a terminal on stdin and stdout; redirected output is refused so pipelines never receive ANSI control bytes. Evidence text is escaped before it reaches the terminal, and the raw/alternate screen is restored on exit, error, and panic paths. Press ? inside for the key list."
    )]
    Tui(TuiArgs),
}

#[derive(Args)]
pub struct TuiArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Revision (parse run) to browse; defaults to the newest revision.
    #[arg(long)]
    pub revision: Option<String>,
}

#[derive(Args)]
pub struct AnalyzeArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Revision (parse run) to analyze; defaults to the newest revision.
    #[arg(long)]
    pub revision: Option<String>,
    /// Bounded TOML rule parameters (unknown fields and out-of-range values
    /// are rejected).
    #[arg(long)]
    pub rules: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum CaseCommand {
    /// Create a new case directory. The path must end in `.ghosttrace-case`.
    Create(CaseCreateArgs),
}

#[derive(Args)]
pub struct CaseCreateArgs {
    /// Case directory, e.g. `/cases/investigation.ghosttrace-case`.
    #[arg(long)]
    pub case: PathBuf,
    /// Investigator-visible case label.
    #[arg(long)]
    pub label: String,
    /// Display timezone (IANA name); never applied to source timestamps.
    #[arg(long, default_value = "UTC")]
    pub timezone: String,
    /// Free-text case description.
    #[arg(long, default_value = "")]
    pub description: String,
}

#[derive(Args)]
pub struct ScanArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Evidence root to capture. Repeat for multiple roots.
    #[arg(long = "source", required = true)]
    pub sources: Vec<PathBuf>,
    /// How the source was reached. `live-best-effort` is explicitly best effort.
    #[arg(long, value_enum, default_value_t = MethodArg::ProtectedCopy)]
    pub method: MethodArg,
    /// Where the source came from, as claimed by the investigator.
    #[arg(long, default_value = "not recorded")]
    pub claimed_source: String,
    /// Maximum traversal depth below each root.
    #[arg(long, default_value_t = 64)]
    pub max_depth: u32,
    /// Maximum entries visited per root.
    #[arg(long, default_value_t = 1_000_000)]
    pub max_entries: u64,
    /// Files larger than this are recorded as excluded, never read.
    #[arg(long, default_value_t = 16 * 1024 * 1024 * 1024)]
    pub max_file_bytes: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum MethodArg {
    ProtectedCopy,
    LiveBestEffort,
}

#[derive(Args)]
pub struct TimelineArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Relative window ending at the case-latest event, e.g. `24h`, `90m`, `7d`.
    #[arg(long)]
    pub last: Option<String>,
    /// Explicit exclusive upper bound (RFC 3339).
    #[arg(long)]
    pub until: Option<String>,
    /// Exact event kind filter (e.g. `file.observed`).
    #[arg(long)]
    pub kind: Option<String>,
    /// Exact host-claim filter.
    #[arg(long)]
    pub host: Option<String>,
    /// Exact parser/adapter identity filter (`parse_runs.parser_id`).
    #[arg(long)]
    pub source: Option<String>,
    /// The explicit unresolved-time view.
    #[arg(long)]
    pub unresolved: bool,
    /// Revision (parse run) to read; defaults to the newest revision of the
    /// selected acquisition. Capture metadata events alone use the literal
    /// `r1`, and it is always accepted.
    #[arg(long)]
    pub revision: Option<String>,
    #[arg(long, default_value_t = EventQuery::DEFAULT_LIMIT)]
    pub limit: u32,
    /// Opaque cursor from a previous page (`seconds:nanos:event_id`).
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Args)]
pub struct SearchArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Search text: words, "quoted phrases", and `-term` to exclude.
    #[arg(long, allow_hyphen_values = true)]
    pub text: String,
    /// Exact event kind filter (e.g. `browser.visit`).
    #[arg(long)]
    pub kind: Option<String>,
    /// Exact host-claim filter.
    #[arg(long)]
    pub host: Option<String>,
    /// Exact parser/adapter identity filter (`parse_runs.parser_id`).
    #[arg(long)]
    pub source: Option<String>,
    /// Inclusive lower bound on chosen time (Unix seconds).
    #[arg(long, allow_hyphen_values = true)]
    pub after: Option<i64>,
    /// Exclusive upper bound on chosen time (Unix seconds).
    #[arg(long)]
    pub before: Option<i64>,
    /// The explicit unresolved-time view.
    #[arg(long)]
    pub unresolved: bool,
    /// Revision (parse run) to read; defaults to the newest of the latest
    /// acquisition.
    #[arg(long)]
    pub revision: Option<String>,
    #[arg(long, default_value_t = EventQuery::DEFAULT_LIMIT)]
    pub limit: u32,
    /// Opaque cursor from a previous page (`seconds:nanos:event_id`).
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Args)]
pub struct DiffArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Earlier acquisition ID.
    #[arg(long)]
    pub before: String,
    /// Later acquisition ID.
    #[arg(long)]
    pub after: String,
    #[arg(long, default_value_t = DiffQuery::DEFAULT_LIMIT)]
    pub limit: u32,
    /// Opaque path cursor from a previous page.
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Manifest file to verify (default: the manifest of --acquisition or the latest).
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Acquisition whose manifest to verify when --manifest is omitted.
    #[arg(long)]
    pub acquisition: Option<String>,
}

#[derive(Args)]
pub struct ReportArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Directory that will receive the report directory.
    #[arg(long)]
    pub output: PathBuf,
    /// Acquisition to report (default: the latest).
    #[arg(long)]
    pub acquisition: Option<String>,
    /// Parse run (revision) whose events the timeline shows. Defaults to the
    /// newest parse run of the acquisition; an earlier revision stays
    /// selectable so an old report can be reproduced exactly.
    #[arg(long)]
    pub revision: Option<String>,
    /// Maximum timeline events included in the report.
    #[arg(long, default_value_t = 500)]
    pub limit: u32,
    /// Fixed report identity; defaults to `report-<acquisition>-<unix seconds>`.
    #[arg(long)]
    pub report_id: Option<String>,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Captured relative path, e.g. `logs/app.jsonl`.
    #[arg(long)]
    pub path: Option<String>,
    /// Captured evidence object ID (instead of --path).
    #[arg(long)]
    pub object: Option<String>,
    /// Acquisition to read (default: the latest).
    #[arg(long)]
    pub acquisition: Option<String>,
    /// Declare the format instead of relying on signature detection. Journal
    /// exports come from an explicit `journalctl -o export` acquisition.
    #[arg(long, value_enum)]
    pub format: Option<FormatArg>,
    /// JSONL: field holding the record time.
    #[arg(long, default_value = "ts")]
    pub time_field: String,
    /// JSONL: how that time field is encoded.
    #[arg(long, value_enum, default_value_t = TimeFormatArg::Rfc3339)]
    pub time_format: TimeFormatArg,
    /// JSONL: field holding the human-readable summary.
    #[arg(long)]
    pub message_field: Option<String>,
    /// JSONL: field holding the claimed host.
    #[arg(long)]
    pub host_field: Option<String>,
    /// JSONL: field holding the event kind.
    #[arg(long)]
    pub kind_field: Option<String>,
    /// JSONL: kind used when no kind field is mapped.
    #[arg(long, default_value = "log.record")]
    pub default_kind: String,
    /// Syslog: IANA zone for RFC 3164 wall-clock headers.
    #[arg(long)]
    pub timezone: Option<String>,
    /// Syslog: year for RFC 3164 headers (never inferred).
    #[arg(long)]
    pub year: Option<i32>,
    /// Per-record byte bound; larger records are reported, not parsed.
    #[arg(long, default_value_t = DEFAULT_MAX_RECORD_BYTES)]
    pub max_record_bytes: usize,
    /// Maximum records read from one object.
    #[arg(long, default_value_t = DEFAULT_MAX_RECORDS)]
    pub max_records: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    Jsonl,
    #[value(name = "syslog-5424")]
    Syslog5424,
    #[value(name = "syslog-3164")]
    Syslog3164,
    #[value(name = "journal-export")]
    JournalExport,
    #[value(name = "browser")]
    Browser,
}

impl FormatArg {
    fn format(self) -> LogFormat {
        match self {
            FormatArg::Jsonl => LogFormat::Jsonl,
            FormatArg::Syslog5424 => LogFormat::Syslog5424,
            FormatArg::Syslog3164 => LogFormat::Syslog3164,
            FormatArg::JournalExport => LogFormat::JournalExport,
            FormatArg::Browser => LogFormat::Browser,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum TimeFormatArg {
    Rfc3339,
    UnixSeconds,
    UnixMillis,
    UnixMicros,
    UnixNanos,
}

impl TimeFormatArg {
    fn time_format(self) -> TimeFormat {
        match self {
            TimeFormatArg::Rfc3339 => TimeFormat::Rfc3339,
            TimeFormatArg::UnixSeconds => TimeFormat::UnixSeconds,
            TimeFormatArg::UnixMillis => TimeFormat::UnixMillis,
            TimeFormatArg::UnixMicros => TimeFormat::UnixMicros,
            TimeFormatArg::UnixNanos => TimeFormat::UnixNanos,
        }
    }
}

#[derive(Args)]
pub struct StatusArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
}

#[derive(Serialize)]
struct CaseCreated {
    case_id: String,
    case_dir: String,
    label: String,
    display_timezone: String,
}

#[derive(Serialize)]
struct CoverageCounts {
    captured: u64,
    excluded: u64,
    inaccessible: u64,
    unstable: u64,
    vanished: u64,
    unsupported: u64,
    unobserved: u64,
    hardlink_aliases: u64,
}

#[derive(Serialize)]
struct Gap {
    path: String,
    status: &'static str,
    code: &'static str,
    detail: String,
}

#[derive(Serialize)]
struct ScanOutput {
    acquisition_id: String,
    state: &'static str,
    objects: usize,
    bytes: u64,
    coverage: CoverageCounts,
    gaps: Vec<Gap>,
    manifest: Option<String>,
}

#[derive(Serialize)]
struct AcquisitionRow {
    id: String,
    method: String,
    state: String,
    started_seconds: Option<i64>,
    ended_seconds: Option<i64>,
    objects: i64,
    coverage_rows: i64,
}

#[derive(Serialize)]
struct RecoverableRow {
    job_id: String,
    kind: String,
}

#[derive(Serialize)]
struct RecoveryRow {
    abandoned_staging: usize,
    orphan_objects: usize,
}

#[derive(Serialize)]
struct TimelineOutput {
    revision: String,
    resolved_view: bool,
    after_seconds: Option<i64>,
    before_seconds: Option<i64>,
    anchor_seconds: Option<i64>,
    rows: Vec<EventRow>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct SearchOutput {
    /// The operator's search text, echoed for the record.
    text: String,
    revision: String,
    resolved_view: bool,
    rows: Vec<EventRow>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct VerifyOutput {
    verified: bool,
    manifest_id: String,
    acquisition_id: String,
    format: String,
    objects_verified: usize,
    total_bytes: u64,
    captured: u64,
    gaps: u64,
    signed: bool,
}

#[derive(Serialize)]
struct ReportOutput {
    report_id: String,
    format: String,
    directory: String,
    json: String,
    html: String,
    objects: usize,
    events: usize,
    gaps: u64,
}

#[derive(Serialize)]
struct StatusOutput {
    case_id: String,
    display_timezone: String,
    acquisitions: Vec<AcquisitionRow>,
    coverage: BTreeMap<String, i64>,
    recoverable_jobs: Vec<RecoverableRow>,
    recovery: RecoveryRow,
}

/// Run one parsed command and return the process exit code.
pub fn run(cli: Cli) -> u8 {
    match cli {
        Cli::SqliteInfo => {
            output::emit_json(&ghosttrace_core::sqlite_report::sqlite_report());
            EXIT_OK
        }
        Cli::Case {
            command: CaseCommand::Create(args),
        } => case_create(args),
        Cli::Scan(args) => scan(args),
        Cli::Status(args) => status(args),
        Cli::Timeline(args) => timeline(args),
        Cli::Search(args) => search(args),
        Cli::Diff(args) => diff(args),
        Cli::Verify(args) => verify(args),
        Cli::Report(args) => report(args),
        Cli::Import(args) => import(args),
        Cli::Analyze(args) => analyze(args),
        Cli::Tui(args) => crate::tui::run(&args.case, args.revision),
    }
}

fn analyze(args: AnalyzeArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    let revision = match args.revision {
        Some(revision) => revision,
        None => match reader.latest_revision(None) {
            Ok(Some(revision)) => revision,
            Ok(None) => {
                output::emit_error(
                    "invalid_usage",
                    "this case has no parse run yet; import an object or scan the case first",
                );
                return EXIT_USAGE;
            }
            Err(error) => return fail(&error),
        },
    };
    let config = match args.rules {
        Some(path) => {
            let parsed = std::fs::read_to_string(&path)
                .map_err(|error| {
                    CoreError::InvalidInput(format!("read rule config {}: {error}", path.display()))
                })
                .and_then(|text| RuleConfig::from_toml(&text));
            match parsed {
                Ok(config) => config,
                Err(error) => return fail_input(&error),
            }
        }
        None => RuleConfig::default(),
    };
    let report = match session.analyze(&AnalysisRequest { revision, config }) {
        Ok(report) => report,
        Err(error) => return fail_input(&error),
    };
    output::emit_json(&report);
    if report.state == "partial" {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    }
}

fn import(args: ImportArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    if args.path.is_some() == args.object.is_some() {
        output::emit_error("invalid_request", "pass exactly one of --path or --object");
        return EXIT_USAGE;
    }
    if !(1..=ingest::MAX_RECORD_BYTES_LIMIT).contains(&args.max_record_bytes) {
        output::emit_error(
            "invalid_request",
            &format!(
                "--max-record-bytes must be between 1 and {}",
                ingest::MAX_RECORD_BYTES_LIMIT
            ),
        );
        return EXIT_USAGE;
    }
    if args.max_records == 0 {
        output::emit_error("invalid_request", "--max-records must be at least 1");
        return EXIT_USAGE;
    }
    let request = ImportRequest {
        path: args.path,
        evidence_id: args.object,
        acquisition_id: args.acquisition,
        format: args.format.map(FormatArg::format),
        jsonl: JsonlConfig {
            time_field: args.time_field,
            time_format: TimeFormatArg::time_format(args.time_format),
            message_field: args.message_field,
            host_field: args.host_field,
            kind_field: args.kind_field,
            default_kind: args.default_kind,
        },
        syslog: SyslogConfig {
            timezone: args.timezone,
            year: args.year,
        },
        max_record_bytes: args.max_record_bytes,
        max_records: args.max_records,
        cancelled: &INTERRUPTED,
    };
    install_interrupt_handler();
    let outcome = ingest::run_import(&reader, session.writer(), session.layout().root(), &request);
    INTERRUPTED.store(false, Ordering::SeqCst);
    match outcome {
        Ok(outcome) => {
            if outcome.state == "partial" {
                eprintln!(
                    "import partial: {} diagnostics recorded (first at {})",
                    outcome.diagnostics_total,
                    outcome
                        .diagnostics
                        .first()
                        .map(|diagnostic| diagnostic.code.as_str())
                        .unwrap_or("unknown")
                );
            }
            if outcome.state == "cancelled" {
                eprintln!("import cancelled: the run is recorded as cancelled");
            }
            let code = if outcome.state == "completed" {
                EXIT_OK
            } else {
                EXIT_PARTIAL
            };
            output::emit_json(&outcome);
            code
        }
        Err(CoreError::InvalidInput(message)) | Err(CoreError::Unsupported(message)) => {
            output::emit_error("invalid_request", &message);
            EXIT_USAGE
        }
        Err(error) => fail(&error),
    }
}

fn verify(args: VerifyArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let case_root = session.layout().root().to_path_buf();
    let manifest_path = match args.manifest {
        Some(path) => path,
        None => {
            let reader = match session.reader() {
                Ok(reader) => reader,
                Err(error) => return fail(&error),
            };
            let acquisition = match args.acquisition {
                Some(id) => id,
                None => {
                    let latest = reader
                        .connection()
                        .query_row(
                            "SELECT id FROM acquisitions
                             ORDER BY started_seconds DESC, id DESC LIMIT 1",
                            [],
                            |row| row.get::<_, String>(0),
                        )
                        .map_err(|error| {
                            CoreError::InvalidInput(format!("no acquisition in this case: {error}"))
                        });
                    match latest {
                        Ok(id) => id,
                        Err(error) => return fail(&error),
                    }
                }
            };
            session
                .layout()
                .manifests_root()
                .join(format!("manifest-{acquisition}.json"))
        }
    };

    match ManifestV1::verify_file(&manifest_path, &case_root) {
        Ok(result) => {
            output::emit_json(&VerifyOutput {
                verified: true,
                manifest_id: result.manifest_id,
                acquisition_id: result.acquisition_id,
                format: result.format,
                objects_verified: result.objects_verified,
                total_bytes: result.total_bytes,
                captured: result.captured,
                gaps: result.gaps,
                signed: false,
            });
            EXIT_OK
        }
        Err(error) => {
            output::emit_error(error.code(), &error.to_string());
            match error {
                CoreError::IntegrityMismatch
                | CoreError::CorruptEvidence
                | CoreError::Unsupported(_) => EXIT_VERIFY,
                _ => EXIT_FAILED,
            }
        }
    }
}

fn report(args: ReportArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    let context = ReportContext {
        case_id: session.case_id().to_string(),
        label: session.config().label.clone(),
        display_timezone: session.config().display_timezone.clone(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_by: "ghosttrace-cli".to_string(),
    };
    let selection = ReportSelection {
        acquisition_id: args.acquisition,
        revision: args.revision,
        event_limit: args.limit,
    };
    let mut report = match reports::build_report(&reader, &context, &selection) {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };
    if let Some(report_id) = args.report_id {
        if !report_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            || report_id.starts_with('.')
        {
            output::emit_error(
                "invalid_report_id",
                "report id may only contain letters, digits, '-', '_' and '.'",
            );
            return EXIT_USAGE;
        }
        report.report_id = report_id;
    }
    match reports::publish(&report, &args.output) {
        Ok(published) => {
            output::emit_json(&ReportOutput {
                report_id: report.report_id.clone(),
                format: report.format.clone(),
                directory: native_path(&published.directory).encoded(),
                json: native_path(&published.json_path).encoded(),
                html: native_path(&published.html_path).encoded(),
                objects: report.objects.len(),
                events: report.timeline.len(),
                gaps: report.coverage.total_gaps(),
            });
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

fn case_create(args: CaseCreateArgs) -> u8 {
    let (parent, id) = match split_case_directory(&args.case) {
        Ok(parts) => parts,
        Err(message) => {
            output::emit_error("invalid_layout", &message);
            return EXIT_USAGE;
        }
    };
    let spec = CreateCaseSpec {
        label: args.label,
        display_timezone: args.timezone,
        description: args.description,
    };
    match CaseSession::create(parent, &id, spec) {
        Ok(session) => {
            let created = CaseCreated {
                case_id: session.case_id().to_string(),
                case_dir: native_path(session.layout().root()).encoded(),
                label: session.config().label.clone(),
                display_timezone: session.config().display_timezone.clone(),
            };
            output::emit_json(&created);
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

fn scan(args: ScanArgs) -> u8 {
    let session = match CaseSession::open(&args.case) {
        Ok((session, _report)) => session,
        Err(error) => return fail(&error),
    };
    let roots: Vec<CaptureRoot> = args
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| CaptureRoot {
            native: native_path(source),
            label: format!("source-{}", index + 1),
        })
        .collect();
    let spec = CaptureSpec {
        roots,
        follow_symlinks: false,
        max_depth: args.max_depth,
        max_entries: args.max_entries,
        max_file_bytes: args.max_file_bytes,
        case_directory: session.layout().root().to_path_buf(),
    };
    if let Err(error) = spec.validate().into_result() {
        return fail(&error);
    }
    let method = match args.method {
        MethodArg::ProtectedCopy => AcquisitionMethod::ProtectedCopy,
        MethodArg::LiveBestEffort => AcquisitionMethod::LiveBestEffort,
    };
    let options = AcquisitionOptions::new(method, args.claimed_source, &spec);
    transport_warning(method);

    let progress = CopyProgress::new();
    install_interrupt_handler();
    output::emit_progress(0, 0);
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut last = (0u64, 0u64);
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = run_acquisition(&session, &spec, &options, &progress);
            let _ = sender.send(result);
        });
        loop {
            if INTERRUPTED.swap(false, Ordering::SeqCst) {
                progress.cancel();
                eprintln!("interrupt received: finishing the current file, then stopping");
            }
            match receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(result) => break result,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let snapshot = (
                        progress.bytes_copied.load(Ordering::Relaxed),
                        progress.objects_published.load(Ordering::Relaxed),
                    );
                    if snapshot != last {
                        output::emit_progress(snapshot.0, snapshot.1);
                        last = snapshot;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(CoreError::Internal("acquisition thread vanished".into()));
                }
            }
        }
    });

    let report = match outcome {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };
    output::emit_progress(
        progress.bytes_copied.load(Ordering::Relaxed),
        progress.objects_published.load(Ordering::Relaxed),
    );

    let coverage = &report.coverage;
    let gaps = coverage
        .examples
        .iter()
        .map(|outcome| Gap {
            path: outcome.native_relative.encoded(),
            status: outcome.status.as_str(),
            code: outcome.reason.code(),
            detail: output::escape(outcome.reason.detail()),
        })
        .collect();
    let state = match report.state {
        ghosttrace_core::domain::case::AcquisitionState::Completed => "completed",
        ghosttrace_core::domain::case::AcquisitionState::Partial => "partial",
        ghosttrace_core::domain::case::AcquisitionState::Cancelled => "cancelled",
        ghosttrace_core::domain::case::AcquisitionState::Failed => "failed",
        ghosttrace_core::domain::case::AcquisitionState::Queued => "queued",
        ghosttrace_core::domain::case::AcquisitionState::Running => "running",
    };
    let bytes = report
        .manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .objects
                .iter()
                .map(|object| object.byte_length)
                .sum()
        })
        .unwrap_or_default();
    output::emit_json(&ScanOutput {
        acquisition_id: report.acquisition_id.clone(),
        state,
        objects: report.published_objects(),
        bytes,
        coverage: CoverageCounts {
            captured: coverage.captured,
            excluded: coverage.excluded,
            inaccessible: coverage.inaccessible,
            unstable: coverage.unstable,
            vanished: coverage.vanished,
            unsupported: coverage.unsupported,
            unobserved: coverage.unobserved,
            hardlink_aliases: coverage.hardlink_aliases,
        },
        gaps,
        manifest: report
            .manifest_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(str::to_string),
    });
    eprintln!(
        "scan {state}: {} objects, {} captured, {} gaps",
        report.published_objects(),
        coverage.captured,
        coverage.gaps()
    );
    match report.state {
        ghosttrace_core::domain::case::AcquisitionState::Completed => EXIT_OK,
        ghosttrace_core::domain::case::AcquisitionState::Partial
        | ghosttrace_core::domain::case::AcquisitionState::Cancelled => EXIT_PARTIAL,
        _ => EXIT_FAILED,
    }
}

fn status(args: StatusArgs) -> u8 {
    let (session, open_report) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    let connection = reader.connection();

    let acquisitions = match connection
        .prepare(
            "SELECT a.id, a.method, a.state, a.started_seconds, a.ended_seconds,
                    (SELECT count(*) FROM evidence_objects o WHERE o.acquisition_id = a.id),
                    (SELECT count(*) FROM coverage c WHERE c.acquisition_id = a.id)
             FROM acquisitions a
             ORDER BY a.started_seconds, a.id",
        )
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok(AcquisitionRow {
                        id: row.get(0)?,
                        method: row.get(1)?,
                        state: row.get(2)?,
                        started_seconds: row.get(3)?,
                        ended_seconds: row.get(4)?,
                        objects: row.get(5)?,
                        coverage_rows: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()
        }) {
        Ok(rows) => rows,
        Err(error) => {
            return fail(&CoreError::Storage(format!("status acquisitions: {error}")));
        }
    };

    let coverage = match connection
        .prepare("SELECT status, count(*) FROM coverage GROUP BY status ORDER BY status")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()
        }) {
        Ok(rows) => rows.into_iter().collect(),
        Err(error) => return fail(&CoreError::Storage(format!("status coverage: {error}"))),
    };

    let recovery = match inspect_recovery(session.layout(), &reader) {
        Ok(report) => RecoveryRow {
            abandoned_staging: report.abandoned_staging.len(),
            orphan_objects: report.orphan_objects.len(),
        },
        Err(error) => return fail(&error),
    };

    let recoverable_jobs = open_report
        .recoverable_jobs
        .iter()
        .map(|job| RecoverableRow {
            job_id: job.job_id.clone(),
            kind: format!("{:?}", job.kind).to_lowercase(),
        })
        .collect();

    output::emit_json(&StatusOutput {
        case_id: session.case_id().to_string(),
        display_timezone: session.config().display_timezone.clone(),
        acquisitions,
        coverage,
        recoverable_jobs,
        recovery,
    });
    EXIT_OK
}

fn timeline(args: TimelineArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    // Resolve the revision to read: the operator's choice, or the newest
    // revision of the latest acquisition. A revision is echoed back so the
    // caller can tell which normalization produced the page.
    let revision = match args.revision.as_deref() {
        Some(revision) => revision.to_string(),
        None => match reader.latest_revision(None) {
            Ok(Some(revision)) => revision,
            Ok(None) => {
                output::emit_error(
                    "invalid_usage",
                    "this case has no parse run yet; import an object or scan the case first",
                );
                return EXIT_USAGE;
            }
            Err(error) => return fail(&error),
        },
    };
    let before_seconds = match args.until.as_deref().map(parse_instant) {
        Some(Ok(seconds)) => Some(seconds),
        Some(Err(message)) => {
            output::emit_error("invalid_usage", &message);
            return EXIT_USAGE;
        }
        None => None,
    };
    let window = match args.last.as_deref().map(parse_window) {
        Some(Ok(seconds)) => Some(seconds),
        Some(Err(message)) => {
            output::emit_error("invalid_usage", &message);
            return EXIT_USAGE;
        }
        None => None,
    };
    let anchor_seconds = if window.is_some() || before_seconds.is_some() {
        // Same revision as the view below it, so a relative window ends at the
        // newest event that view can actually see.
        match before_seconds.map_or_else(
            || reader.latest_chosen_seconds(Some(&revision)),
            |seconds| Ok(Some(seconds)),
        ) {
            Ok(anchor) => anchor,
            Err(error) => return fail(&error),
        }
    } else {
        None
    };
    let after_seconds = match (window, anchor_seconds) {
        (Some(window), Some(anchor)) => Some(anchor.saturating_sub(window)),
        _ => None,
    };
    let cursor = match args.cursor.as_deref().map(parse_cursor) {
        Some(Ok(cursor)) => Some(cursor),
        Some(Err(message)) => {
            output::emit_error("invalid_usage", &message);
            return EXIT_USAGE;
        }
        None => None,
    };
    let query = EventQuery {
        revision: revision.clone(),
        kind: args.kind,
        host: args.host,
        source: args.source,
        after_seconds,
        before_seconds,
        unresolved_only: args.unresolved,
        limit: args.limit,
        after: cursor,
    };
    let page = match reader.query_events(&session.config().display_timezone, &query) {
        Ok(page) => page,
        Err(error) => return fail(&error),
    };
    output::emit_json(&TimelineOutput {
        revision,
        resolved_view: !args.unresolved,
        after_seconds,
        before_seconds,
        anchor_seconds,
        rows: page.rows,
        next_cursor: page.next_cursor.map(format_cursor),
    });
    EXIT_OK
}

fn search(args: SearchArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };

    // Validate the grammar before the revision or the case is touched, so a
    // bad expression is a usage error and never a half-formed query.
    let text = match ghosttrace_core::storage::search::validate_search_text(&args.text) {
        Ok(text) => text,
        Err(ghosttrace_core::error::CoreError::InvalidInput(message)) => {
            output::emit_error("invalid_search_text", &message);
            return EXIT_USAGE;
        }
        Err(error) => return fail(&error),
    };

    let revision = match args.revision.as_deref() {
        Some(revision) => revision.to_string(),
        None => match reader.latest_revision(None) {
            Ok(Some(revision)) => revision,
            Ok(None) => {
                output::emit_error(
                    "invalid_usage",
                    "this case has no parse run yet; import an object or scan the case first",
                );
                return EXIT_USAGE;
            }
            Err(error) => return fail(&error),
        },
    };
    let cursor = match args.cursor.as_deref().map(parse_cursor) {
        Some(Ok(cursor)) => Some(cursor),
        Some(Err(message)) => {
            output::emit_error("invalid_usage", &message);
            return EXIT_USAGE;
        }
        None => None,
    };
    let query = EventQuery {
        revision,
        kind: args.kind,
        host: args.host,
        source: args.source,
        after_seconds: args.after,
        before_seconds: args.before,
        unresolved_only: args.unresolved,
        limit: args.limit,
        after: cursor,
    };
    let page = match ghosttrace_core::storage::search::search_events(
        &reader,
        &session.config().display_timezone,
        &query,
        &text,
    ) {
        Ok(page) => page,
        Err(error) => return fail(&error),
    };
    output::emit_json(&SearchOutput {
        text: text.input,
        revision: query.revision,
        resolved_view: !args.unresolved,
        rows: page.rows,
        next_cursor: page.next_cursor.map(format_cursor),
    });
    EXIT_OK
}

fn diff(args: DiffArgs) -> u8 {
    let (session, _open) = match CaseSession::open(&args.case) {
        Ok(open) => open,
        Err(error) => return fail(&error),
    };
    let reader = match session.reader() {
        Ok(reader) => reader,
        Err(error) => return fail(&error),
    };
    let query = DiffQuery {
        after: args.cursor,
        limit: args.limit,
    };
    let report: DiffReport = match compare_acquisitions(&reader, &args.before, &args.after, &query)
    {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };
    output::emit_json(&report);
    eprintln!(
        "diff {} -> {}: {} unchanged, {} changed, {} appeared, {} not present, {} unknown",
        report.before_acquisition,
        report.after_acquisition,
        report.summary.unchanged,
        report.summary.content_changed
            + report.summary.content_changed_equal_metadata
            + report.summary.metadata_changed,
        report.summary.appeared,
        report.summary.not_present_in_captured_scope,
        report.summary.unknown
    );
    EXIT_OK
}

fn parse_window(text: &str) -> Result<i64, String> {
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    let value: i64 = digits
        .parse()
        .map_err(|_| format!("invalid window `{text}`; use e.g. 24h, 90m, 7d"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        _ => {
            return Err(format!(
                "invalid window unit in `{text}`; use s, m, h, or d"
            ));
        }
    };
    if value <= 0 {
        return Err(format!("invalid window `{text}`; must be positive"));
    }
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("window `{text}` is too large"))
}

pub(crate) fn parse_instant(text: &str) -> Result<i64, String> {
    chrono::DateTime::parse_from_rfc3339(text)
        .map(|instant| instant.timestamp())
        .map_err(|_| {
            format!("invalid instant `{text}`; expected RFC 3339, e.g. 2026-10-27T12:00:00Z")
        })
}

fn parse_cursor(text: &str) -> Result<TimeCursor, String> {
    let mut parts = text.splitn(3, ':');
    let seconds = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| format!("invalid cursor `{text}`; expected seconds:nanos:event_id"))?;
    let nanos = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or_else(|| format!("invalid cursor `{text}`; expected seconds:nanos:event_id"))?;
    let event_id = parts
        .next()
        .ok_or_else(|| format!("invalid cursor `{text}`; expected seconds:nanos:event_id"))?;
    Ok(TimeCursor {
        seconds,
        nanos,
        event_id: event_id.to_string(),
    })
}

fn format_cursor(cursor: TimeCursor) -> String {
    format!("{}:{}:{}", cursor.seconds, cursor.nanos, cursor.event_id)
}

fn fail(error: &CoreError) -> u8 {
    output::emit_error(error.code(), &error.to_string());
    EXIT_FAILED
}

/// Rejected user input (parameters, paths, bounds) is a usage error, not an
/// internal failure. Storage and integrity problems stay exit 1.
fn fail_input(error: &CoreError) -> u8 {
    output::emit_error(error.code(), &error.to_string());
    match error {
        CoreError::InvalidInput(_) => EXIT_USAGE,
        _ => EXIT_FAILED,
    }
}

/// The plan requires the trade-off to be visible where the choice is made.
fn transport_warning(method: AcquisitionMethod) {
    match method {
        AcquisitionMethod::ProtectedCopy => eprintln!(
            "source method: protected copy (recommended). Verify the copy was made by a \
             write-blocked or equivalent process before relying on this case in production."
        ),
        AcquisitionMethod::LiveBestEffort => eprintln!(
            "source method: live best effort. Files can change or vanish during capture; \
             coverage records what was seen, and access-time metadata may be affected."
        ),
    }
}

/// Split `.../name.ghosttrace-case` into its parent and case ID.
fn split_case_directory(path: &Path) -> Result<(PathBuf, String), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "case directory must have a UTF-8 file name".to_string())?;
    let id = name
        .strip_suffix(CASE_DIR_SUFFIX)
        .ok_or_else(|| format!("case directory must end with {CASE_DIR_SUFFIX}"))?;
    if id.is_empty() {
        return Err(format!(
            "case directory needs a name before {CASE_DIR_SUFFIX}"
        ));
    }
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
    Ok((
        parent.unwrap_or(Path::new(".")).to_path_buf(),
        id.to_string(),
    ))
}

#[cfg(unix)]
fn native_path(path: &Path) -> NativePath {
    use std::os::unix::ffi::OsStrExt;
    NativePath::unix(path.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn native_path(path: &Path) -> NativePath {
    use std::os::windows::ffi::OsStrExt;
    NativePath::windows(path.as_os_str().encode_wide().collect::<Vec<u16>>())
}

#[cfg(unix)]
fn install_interrupt_handler() {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
    // An async-signal-safe flag: the worker observes it between chunks and the
    // command then reports a cancelled, partial acquisition.
    unsafe {
        let action = SigAction::new(
            SigHandler::Handler(mark_interrupted),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let _ = sigaction(Signal::SIGINT, &action);
    }
}

#[cfg(unix)]
extern "C" fn mark_interrupted(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(not(unix))]
fn install_interrupt_handler() {}
