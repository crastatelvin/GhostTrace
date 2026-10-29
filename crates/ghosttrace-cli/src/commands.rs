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
use ghosttrace_core::integrity::keys::{generate_key_file, import_key_file, load_key_file};
use ghosttrace_core::integrity::signature::{
    KeyTrust, ManifestStatus, SignatureEnvelope, SignatureStatus, TrustedKeys, sidecar_path,
    verify_manifest,
};
use ghosttrace_core::reports::csv;
use ghosttrace_core::reports::package::{PackageRequest, publish_package, verify_package};
use ghosttrace_core::reports::redact::{RedactionPolicy, redact_report};
use ghosttrace_core::reports::{self, ReportContext, ReportSelection};
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::CASE_DIR_SUFFIX;
use ghosttrace_core::storage::backup::{backup_case, restore_case};

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
    /// Generate, import, or inspect an encrypted Ed25519 signing key.
    Key(KeyArgs),
    /// Sign the exact bytes of a stored acquisition manifest.
    #[command(
        long_about = "Sign the exact bytes of a stored acquisition manifest.\n\nThe passphrase is read from the terminal, never from an argument or the environment, and the key is zeroized after use. The detached sidecar records the protocol version, algorithm, manifest digest, public key, fingerprint, and signature; an existing sidecar is never overwritten. A signature proves the bytes were signed by that key, not that the key is yours."
    )]
    Sign(SignArgs),
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
    /// Build a portable evidence package a second person can verify offline.
    #[command(
        long_about = "Build a portable evidence package a second person can verify offline.\n\nThe package contains the acquisition manifest, the stored objects the report cites, the\nreport (JSON, HTML, and spreadsheet-safe CSV), a verifier README, and a SHA-256 inventory\nover every file. --redact applies the same projection as `report`. --key signs the\ninventory with an encrypted Ed25519 key; without it the package is honestly unsigned.\nPublication is atomic and never overwrites an existing package."
    )]
    Package(PackageArgs),
    /// Verify a portable evidence package's inventory and optional signature.
    VerifyPackage(VerifyPackageArgs),
    /// Take a consistent portable backup (SQLite snapshot + referenced objects).
    Backup(BackupArgs),
    /// Restore a verified backup into a new case directory.
    Restore(RestoreArgs),
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
    /// Internal: serve one isolated parse job over stdin/stdout.
    #[command(hide = true)]
    Worker(WorkerArgs),
    /// Browse the timeline, search, event detail, and findings interactively.
    #[command(
        long_about = "Browse the timeline, search, event detail, and findings interactively.\n\nThe TUI reads through the same query and analysis contracts as `timeline`, `search`, and `analyze`, so a selection yields the same recorded event and detail. It needs a terminal on stdin and stdout; redirected output is refused so pipelines never receive ANSI control bytes. Evidence text is escaped before it reaches the terminal, and the raw/alternate screen is restored on exit, error, and panic paths. Press ? inside for the key list."
    )]
    Tui(TuiArgs),
}

#[derive(Args)]
pub struct WorkerArgs {
    /// Protocol version the parent speaks.
    #[arg(long)]
    pub protocol: u32,
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
    /// Detached signature sidecar (default: <manifest>.sig.json when present).
    #[arg(long)]
    pub signature: Option<PathBuf>,
    /// Trusted-key fingerprint list (one 64-character fingerprint per line).
    #[arg(long)]
    pub trust: Option<PathBuf>,
}

#[derive(Args)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommand,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Generate an encrypted Ed25519 signing key (prompts for a passphrase).
    Generate(KeyGenerateArgs),
    /// Re-encrypt an existing encrypted PKCS#8 key under a new passphrase.
    Import(KeyImportArgs),
    /// Print the public key and fingerprint (prompts for the passphrase).
    Public(KeyPublicArgs),
}

#[derive(Args)]
pub struct KeyGenerateArgs {
    /// Destination key file (created with mode 0600; never overwritten).
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct KeyImportArgs {
    /// Existing encrypted PKCS#8 key file.
    #[arg(long = "in")]
    pub input: PathBuf,
    /// Destination key file (must differ from --in; never overwritten).
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct KeyPublicArgs {
    /// Encrypted key file.
    #[arg(long)]
    pub key: PathBuf,
}

#[derive(Args)]
pub struct SignArgs {
    /// Manifest file whose exact stored bytes are signed.
    #[arg(long)]
    pub manifest: PathBuf,
    /// Encrypted key file (passphrase prompted, never an argument).
    #[arg(long)]
    pub key: PathBuf,
    /// Signature sidecar (default: <manifest>.sig.json).
    #[arg(long)]
    pub out: Option<PathBuf>,
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
    /// Also write `report.csv`, a spreadsheet-safe projection.
    #[arg(long)]
    pub csv: bool,
    /// Replace selected values with `[redacted]` in the exported copy.
    #[arg(long = "redact", value_enum, action = clap::ArgAction::Append)]
    pub redact: Vec<RedactCategory>,
}

/// The redaction categories. Each is a projection over the export, never a
/// change to the case or the stored evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RedactCategory {
    CaseLabel,
    SourcePaths,
    ObjectPaths,
    TimelineSummaries,
    TimelineHosts,
}

fn redaction_policy(categories: &[RedactCategory]) -> RedactionPolicy {
    let mut policy = RedactionPolicy::default();
    for category in categories {
        match category {
            RedactCategory::CaseLabel => policy.case_label = true,
            RedactCategory::SourcePaths => policy.source_paths = true,
            RedactCategory::ObjectPaths => policy.object_paths = true,
            RedactCategory::TimelineSummaries => policy.timeline_summaries = true,
            RedactCategory::TimelineHosts => policy.timeline_hosts = true,
        }
    }
    policy
}

#[derive(Args)]
pub struct PackageArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Directory that will receive the package directory.
    #[arg(long)]
    pub output: PathBuf,
    /// Acquisition to package (default: the latest).
    #[arg(long)]
    pub acquisition: Option<String>,
    /// Parse run (revision) whose events the report shows.
    #[arg(long)]
    pub revision: Option<String>,
    /// Maximum timeline events included in the report.
    #[arg(long, default_value_t = 500)]
    pub limit: u32,
    /// Manifest to include (default: the acquisition's manifest).
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Existing manifest signature to include (default: <manifest>.sig.json).
    #[arg(long)]
    pub signature: Option<PathBuf>,
    /// Replace selected values with `[redacted]` in the packaged report.
    #[arg(long = "redact", value_enum, action = clap::ArgAction::Append)]
    pub redact: Vec<RedactCategory>,
    /// Encrypted key that signs the package inventory (prompts for a passphrase).
    #[arg(long)]
    pub key: Option<PathBuf>,
}

#[derive(Args)]
pub struct VerifyPackageArgs {
    /// Package directory to verify.
    #[arg(long)]
    pub package: PathBuf,
    /// Trusted-key fingerprint list (one 64-character fingerprint per line).
    #[arg(long)]
    pub trust: Option<PathBuf>,
}

#[derive(Args)]
pub struct BackupArgs {
    /// Existing case directory.
    #[arg(long)]
    pub case: PathBuf,
    /// Directory that will receive the backup directory.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Verified backup directory.
    #[arg(long)]
    pub backup: PathBuf,
    /// New case directory; must not exist.
    #[arg(long)]
    pub destination: PathBuf,
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
    /// Parser worker binary for risky adapters (default: this executable).
    /// The worker is never searched for on PATH.
    #[arg(long)]
    pub worker: Option<PathBuf>,
    /// Run risky adapters in this process (debugging only; no isolation).
    #[arg(long)]
    pub no_worker: bool,
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
    #[value(name = "evtx")]
    Evtx,
}

impl FormatArg {
    fn format(self) -> LogFormat {
        match self {
            FormatArg::Jsonl => LogFormat::Jsonl,
            FormatArg::Syslog5424 => LogFormat::Syslog5424,
            FormatArg::Syslog3164 => LogFormat::Syslog3164,
            FormatArg::JournalExport => LogFormat::JournalExport,
            FormatArg::Browser => LogFormat::Browser,
            FormatArg::Evtx => LogFormat::Evtx,
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
    manifest_id: Option<String>,
    acquisition_id: Option<String>,
    format: Option<String>,
    objects_verified: Option<usize>,
    total_bytes: Option<u64>,
    captured: Option<u64>,
    gaps: Option<u64>,
    signed: bool,
    signature: String,
    signature_detail: Option<String>,
    key_trust: String,
    key_fingerprint: Option<String>,
    public_key: Option<String>,
    capture_complete: Option<bool>,
    explanation: String,
}

#[derive(Serialize)]
struct KeyOutput {
    path: String,
    public_key: String,
    key_fingerprint: String,
}

#[derive(Serialize)]
struct SignOutput {
    manifest: String,
    signature: String,
    algorithm: String,
    manifest_sha256: String,
    public_key: String,
    key_fingerprint: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    csv: Option<String>,
    redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    redaction: Option<String>,
}

#[derive(Serialize)]
struct PackageOutput {
    package_id: String,
    directory: String,
    inventory: String,
    files: usize,
    total_bytes: u64,
    signed: bool,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
    redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    redaction: Option<String>,
}

#[derive(Serialize)]
struct VerifyPackageOutput {
    verified: bool,
    files_verified: usize,
    total_bytes: u64,
    signature: String,
    signature_detail: Option<String>,
    key_trust: String,
    key_fingerprint: Option<String>,
    case_id: String,
    acquisition_id: String,
    revision: String,
    redacted: bool,
    explanation: String,
}

#[derive(Serialize)]
struct BackupOutput {
    backup_id: String,
    directory: String,
    inventory: String,
    case_id: String,
    schema_version: u32,
    files: usize,
    total_bytes: u64,
}

#[derive(Serialize)]
struct RestoreOutput {
    case_id: String,
    directory: String,
    schema_version: u32,
    objects: usize,
    manifests: usize,
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
        Cli::Key(args) => key(args),
        Cli::Sign(args) => sign(args),
        Cli::Verify(args) => verify(args),
        Cli::Report(args) => report(args),
        Cli::Package(args) => package(args),
        Cli::VerifyPackage(args) => verify_package_command(args),
        Cli::Backup(args) => backup(args),
        Cli::Restore(args) => restore(args),
        Cli::Import(args) => import(args),
        Cli::Analyze(args) => analyze(args),
        Cli::Worker(args) => worker(args),
        Cli::Tui(args) => crate::tui::run(&args.case, args.revision),
    }
}

/// Worker mode: no case, no output but protocol frames. The parent validates
/// everything this process says, so a compromise here cannot reach the case.
fn worker(args: WorkerArgs) -> u8 {
    let expected = ghosttrace_core::worker::protocol::PROTOCOL_VERSION;
    if args.protocol != expected {
        eprintln!(
            "worker protocol {expected} expected, {0} requested",
            args.protocol
        );
        return EXIT_USAGE;
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    ghosttrace_core::worker::protocol::serve(stdin.lock(), stdout.lock())
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
    let worker_path = match (&args.worker, args.no_worker) {
        (Some(_), true) => {
            output::emit_error("invalid_request", "pass either --worker or --no-worker");
            return EXIT_USAGE;
        }
        (Some(path), false) => Some(path.clone()),
        (None, false) => match std::env::current_exe() {
            Ok(path) => Some(path),
            Err(error) => {
                output::emit_error(
                    "invalid_request",
                    &format!("cannot locate the parser worker beside this executable: {error}"),
                );
                return EXIT_USAGE;
            }
        },
        (None, true) => None,
    };
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
        worker: worker_path.clone(),
        isolation_required: !args.no_worker,
        ..ImportRequest::new(&INTERRUPTED)
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
            if outcome.state == "failed" {
                eprintln!("import failed: the run is recorded as failed, never completed");
                output::emit_json(&outcome);
                return EXIT_FAILED;
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

    let trust = match args.trust {
        Some(path) => match TrustedKeys::load(&path) {
            Ok(trust) => Some(trust),
            Err(error) => return fail(&error),
        },
        None => None,
    };
    let report = match verify_manifest(
        &case_root,
        &manifest_path,
        args.signature.as_deref(),
        trust.as_ref(),
    ) {
        Ok(report) => report,
        Err(error) => return fail(&error),
    };

    let verified = report.is_accepted();
    let (manifest_id, acquisition_id, format, objects_verified, total_bytes, captured, gaps) =
        match &report.manifest {
            ManifestStatus::Verified(result) => (
                Some(result.manifest_id.clone()),
                Some(result.acquisition_id.clone()),
                Some(result.format.clone()),
                Some(result.objects_verified),
                Some(result.total_bytes),
                Some(result.captured),
                Some(result.gaps),
            ),
            ManifestStatus::Rejected { .. } => (None, None, None, None, None, None, None),
        };
    let (signature, signature_detail) = match &report.signature {
        SignatureStatus::Absent => ("absent", None),
        SignatureStatus::Valid => ("valid", None),
        SignatureStatus::Invalid(reason) => ("invalid", Some(reason.clone())),
    };
    let key_trust = match report.key_trust {
        KeyTrust::NotApplicable => "not_applicable",
        KeyTrust::Untrusted => "untrusted",
        KeyTrust::Trusted => "trusted",
    };
    let output_report = VerifyOutput {
        verified,
        manifest_id,
        acquisition_id,
        format,
        objects_verified,
        total_bytes,
        captured,
        gaps,
        signed: !matches!(report.signature, SignatureStatus::Absent),
        signature: signature.into(),
        signature_detail,
        key_trust: key_trust.into(),
        key_fingerprint: report.key_fingerprint.clone(),
        public_key: report.public_key.clone(),
        capture_complete: report.capture_complete,
        explanation: explain(&report),
    };
    output::emit_json(&output_report);

    if verified {
        return EXIT_OK;
    }
    let (code, detail) = match &report.manifest {
        ManifestStatus::Rejected { code, detail } => (code.as_str(), detail.clone()),
        ManifestStatus::Verified(_) => match &report.signature {
            SignatureStatus::Invalid(reason) => ("integrity_mismatch", reason.clone()),
            _ => ("integrity_mismatch", "verification failed".into()),
        },
    };
    output::emit_error(code, &detail);
    match code {
        "integrity_mismatch" | "corrupt_evidence" | "unsupported_format" => EXIT_VERIFY,
        _ => EXIT_FAILED,
    }
}

/// One plain-language sentence combining the three independent statuses.
fn explain(report: &ghosttrace_core::integrity::signature::SignedManifestVerification) -> String {
    let mut parts = Vec::new();
    match &report.manifest {
        ManifestStatus::Verified(_) => {
            parts.push("The stored object bytes match the manifest record.".to_string())
        }
        ManifestStatus::Rejected { .. } => {
            parts.push("The stored bytes do not match the manifest record.".to_string())
        }
    }
    match (&report.signature, report.key_trust) {
        (SignatureStatus::Absent, _) => parts.push(
            "No detached signature is present: this proves the bytes match the record, not who \
             produced it."
                .to_string(),
        ),
        (SignatureStatus::Valid, KeyTrust::Trusted) => parts
            .push("The signature is valid and its key is in your trusted-key list.".to_string()),
        (SignatureStatus::Valid, _) => parts.push(
            "The signature is mathematically valid, but the key is not in your trusted-key list: \
             it proves the bytes were signed by that key, not that the key is yours."
                .to_string(),
        ),
        (SignatureStatus::Invalid(reason), _) => parts.push(format!(
            "The signature does not cover these bytes: {reason}."
        )),
    }
    match report.capture_complete {
        Some(true) => parts.push(
            "Capture completeness: no coverage gaps were recorded for the declared scope."
                .to_string(),
        ),
        Some(false) => parts.push(
            "Capture completeness: coverage gaps were recorded; the manifest is complete only for \
             the captured scope."
                .to_string(),
        ),
        None => {}
    }
    parts.join(" ")
}

fn key(args: KeyArgs) -> u8 {
    match args.command {
        KeyCommand::Generate(args) => {
            let first = match prompt_new_passphrase() {
                Ok(passphrase) => passphrase,
                Err(code) => return code,
            };
            match generate_key_file(&args.out, first.as_bytes()) {
                Ok(identity) => {
                    output::emit_json(&KeyOutput {
                        path: args.out.display().to_string(),
                        public_key: identity.public_key,
                        key_fingerprint: identity.key_fingerprint,
                    });
                    EXIT_OK
                }
                Err(error) => fail(&error),
            }
        }
        KeyCommand::Import(args) => {
            let source = match prompt_secret("Current key passphrase: ") {
                Ok(passphrase) => passphrase,
                Err(code) => return code,
            };
            let destination = match prompt_new_passphrase() {
                Ok(passphrase) => passphrase,
                Err(code) => return code,
            };
            match import_key_file(
                &args.input,
                &args.out,
                source.as_bytes(),
                destination.as_bytes(),
            ) {
                Ok(identity) => {
                    output::emit_json(&KeyOutput {
                        path: args.out.display().to_string(),
                        public_key: identity.public_key,
                        key_fingerprint: identity.key_fingerprint,
                    });
                    EXIT_OK
                }
                Err(error) => fail(&error),
            }
        }
        KeyCommand::Public(args) => {
            let passphrase = match prompt_secret("Key passphrase: ") {
                Ok(passphrase) => passphrase,
                Err(code) => return code,
            };
            match load_key_file(&args.key, passphrase.as_bytes()) {
                Ok(key) => {
                    let identity = key.identity();
                    output::emit_json(&KeyOutput {
                        path: args.key.display().to_string(),
                        public_key: identity.public_key,
                        key_fingerprint: identity.key_fingerprint,
                    });
                    EXIT_OK
                }
                Err(error) => fail(&error),
            }
        }
    }
}

fn sign(args: SignArgs) -> u8 {
    let passphrase = match prompt_secret("Key passphrase: ") {
        Ok(passphrase) => passphrase,
        Err(code) => return code,
    };
    let key = match load_key_file(&args.key, passphrase.as_bytes()) {
        Ok(key) => key,
        Err(error) => return fail(&error),
    };
    let bytes = match std::fs::read(&args.manifest) {
        Ok(bytes) => bytes,
        Err(error) => {
            return fail(&CoreError::Storage(format!("manifest read: {error}")));
        }
    };
    let envelope = SignatureEnvelope::sign(&bytes, &key);
    let destination = args.out.unwrap_or_else(|| sidecar_path(&args.manifest));
    match envelope.write_atomic(&destination) {
        Ok(path) => {
            output::emit_json(&SignOutput {
                manifest: args.manifest.display().to_string(),
                signature: path.display().to_string(),
                algorithm: envelope.algorithm,
                manifest_sha256: envelope.manifest_sha256,
                public_key: envelope.public_key,
                key_fingerprint: envelope.key_fingerprint,
            });
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

/// Read a secret from the terminal. Secrets never come from arguments or the
/// environment, and the value is zeroized when it goes out of scope.
fn prompt_secret(label: &str) -> Result<zeroize::Zeroizing<String>, u8> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        output::emit_error(
            "invalid_request",
            "passphrase prompts need a terminal; no passphrase was read",
        );
        return Err(EXIT_USAGE);
    }
    match rpassword::prompt_password(label) {
        Ok(value) => Ok(zeroize::Zeroizing::new(value)),
        Err(error) => {
            output::emit_error(
                "invalid_request",
                &format!("cannot read the passphrase: {error}"),
            );
            Err(EXIT_USAGE)
        }
    }
}

fn prompt_new_passphrase() -> Result<zeroize::Zeroizing<String>, u8> {
    let first = prompt_secret("New key passphrase: ")?;
    let second = prompt_secret("Repeat passphrase: ")?;
    if first.as_str() != second.as_str() {
        output::emit_error("invalid_request", "the passphrases do not match");
        return Err(EXIT_USAGE);
    }
    Ok(first)
}

/// Build one report from recorded rows. The session is returned because the
/// package flow needs the case root and manifests root.
fn build_case_report(
    case: &Path,
    acquisition: Option<String>,
    revision: Option<String>,
    limit: u32,
    generated_by: &str,
) -> Result<(CaseSession, ghosttrace_core::reports::ReportV1), CoreError> {
    let (session, _open) = CaseSession::open(case)?;
    let reader = session.reader()?;
    let context = ReportContext {
        case_id: session.case_id().to_string(),
        label: session.config().label.clone(),
        display_timezone: session.config().display_timezone.clone(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_by: generated_by.to_string(),
    };
    let selection = ReportSelection {
        acquisition_id: acquisition,
        revision,
        event_limit: limit,
    };
    let report = reports::build_report(&reader, &context, &selection)?;
    Ok((session, report))
}

fn redact_if_requested(
    report: ghosttrace_core::reports::ReportV1,
    categories: &[RedactCategory],
) -> Result<
    (
        ghosttrace_core::reports::ReportV1,
        Option<ghosttrace_core::reports::redact::RedactionLedger>,
    ),
    CoreError,
> {
    let policy = redaction_policy(categories);
    if !policy.any() {
        return Ok((report, None));
    }
    let (redacted, ledger) = redact_report(&report, &policy);
    Ok((redacted, Some(ledger)))
}

fn report(args: ReportArgs) -> u8 {
    let (session, report) = match build_case_report(
        &args.case,
        args.acquisition,
        args.revision,
        args.limit,
        "ghosttrace-cli",
    ) {
        Ok(built) => built,
        Err(error) => return fail(&error),
    };
    let _ = session;
    let mut report = report;
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
    let (report, ledger) = match redact_if_requested(report, &args.redact) {
        Ok(redacted) => redacted,
        Err(error) => return fail(&error),
    };
    let mut extras: Vec<(String, String)> = Vec::new();
    if args.csv {
        extras.push(("report.csv".into(), csv::timeline_csv(&report)));
    }
    if let Some(ledger) = &ledger {
        match ledger.to_json() {
            Ok(text) => extras.push(("redaction.json".into(), text)),
            Err(error) => return fail(&error),
        }
    }
    let extras_ref: Vec<(&str, &str)> = extras
        .iter()
        .map(|(name, text)| (name.as_str(), text.as_str()))
        .collect();
    match reports::publish_with(&report, &args.output, &extras_ref) {
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
                csv: args
                    .csv
                    .then(|| native_path(&published.directory.join("report.csv")).encoded()),
                redacted: ledger.is_some(),
                redaction: ledger.as_ref().map(|ledger| ledger.summary()),
            });
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

fn package(args: PackageArgs) -> u8 {
    let (session, report) = match build_case_report(
        &args.case,
        args.acquisition,
        args.revision,
        args.limit,
        "ghosttrace-cli",
    ) {
        Ok(built) => built,
        Err(error) => return fail(&error),
    };
    let (report, ledger) = match redact_if_requested(report, &args.redact) {
        Ok(redacted) => redacted,
        Err(error) => return fail(&error),
    };
    let manifest_path = match args.manifest {
        Some(path) => path,
        None => session
            .layout()
            .manifests_root()
            .join(format!("manifest-{}.json", report.acquisition.id)),
    };
    let manifest_signature = match args.signature {
        Some(path) => Some(path),
        None => {
            let candidate = sidecar_path(&manifest_path);
            candidate.exists().then_some(candidate)
        }
    };
    let key = match args.key {
        Some(path) => {
            let passphrase = match prompt_secret("Key passphrase: ") {
                Ok(passphrase) => passphrase,
                Err(code) => return code,
            };
            match load_key_file(&path, passphrase.as_bytes()) {
                Ok(key) => Some(key),
                Err(error) => return fail(&error),
            }
        }
        None => None,
    };
    let request = PackageRequest {
        case_root: session.layout().root(),
        output: &args.output,
        report: &report,
        redaction: ledger.as_ref(),
        manifest_path: &manifest_path,
        manifest_signature: manifest_signature.as_deref(),
        key: key.as_ref(),
        tool_version: env!("CARGO_PKG_VERSION"),
    };
    match publish_package(request) {
        Ok(published) => {
            output::emit_json(&PackageOutput {
                package_id: published.package_id,
                directory: native_path(&published.directory).encoded(),
                inventory: native_path(&published.inventory_path).encoded(),
                files: published.files.len(),
                total_bytes: published.total_bytes,
                signed: published.signed,
                public_key: published.public_key,
                key_fingerprint: published.key_fingerprint,
                redacted: ledger.is_some(),
                redaction: ledger.as_ref().map(|ledger| ledger.summary()),
            });
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

fn verify_package_command(args: VerifyPackageArgs) -> u8 {
    let trust = match args.trust {
        Some(path) => match TrustedKeys::load(&path) {
            Ok(trust) => Some(trust),
            Err(error) => return fail(&error),
        },
        None => None,
    };
    let verification = match verify_package(&args.package, trust.as_ref()) {
        Ok(verification) => verification,
        Err(error) => {
            return match error {
                CoreError::CorruptEvidence
                | CoreError::IntegrityMismatch
                | CoreError::Unsupported(_) => {
                    output::emit_error(error.code(), &error.to_string());
                    EXIT_VERIFY
                }
                other => fail(&other),
            };
        }
    };
    let (signature, signature_detail) = match &verification.signature {
        SignatureStatus::Absent => ("absent", None),
        SignatureStatus::Valid => ("valid", None),
        SignatureStatus::Invalid(reason) => ("invalid", Some(reason.clone())),
    };
    let key_trust = match verification.key_trust {
        KeyTrust::NotApplicable => "not_applicable",
        KeyTrust::Untrusted => "untrusted",
        KeyTrust::Trusted => "trusted",
    };
    let explanation: &str = match (&verification.signature, verification.key_trust) {
        (SignatureStatus::Absent, _) => {
            "The inventory and every listed file match their digests. The package is unsigned: \
             this proves the files match the inventory, not who produced them."
        }
        (SignatureStatus::Valid, KeyTrust::Trusted) => {
            "Every listed file matches its digest and the inventory signature is valid with a \
             trusted key."
        }
        (SignatureStatus::Valid, _) => {
            "Every listed file matches its digest and the signature is mathematically valid, but \
             the key is not in your trusted-key list."
        }
        (SignatureStatus::Invalid(_), _) => {
            "The inventory signature does not cover these exact bytes; treat the package as \
             changed."
        }
    };
    output::emit_json(&VerifyPackageOutput {
        verified: verification.is_accepted(),
        files_verified: verification.files_verified,
        total_bytes: verification.total_bytes,
        signature: signature.into(),
        signature_detail,
        key_trust: key_trust.into(),
        key_fingerprint: verification.key_fingerprint.clone(),
        case_id: verification.inventory.case_id.clone(),
        acquisition_id: verification.inventory.acquisition_id.clone(),
        revision: verification.inventory.revision.clone(),
        redacted: verification.inventory.redacted,
        explanation: explanation.to_string(),
    });
    if verification.is_accepted() {
        return EXIT_OK;
    }
    let detail = match &verification.signature {
        SignatureStatus::Invalid(reason) => reason.clone(),
        _ => "the package did not verify".to_string(),
    };
    output::emit_error("integrity_mismatch", &detail);
    EXIT_VERIFY
}

fn backup(args: BackupArgs) -> u8 {
    match backup_case(&args.case, &args.output, env!("CARGO_PKG_VERSION")) {
        Ok(published) => {
            let backup_id = published
                .directory
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            output::emit_json(&BackupOutput {
                backup_id,
                directory: native_path(&published.directory).encoded(),
                inventory: native_path(&published.inventory_path).encoded(),
                case_id: published.case_id,
                schema_version: published.schema_version,
                files: published.files.len(),
                total_bytes: published.total_bytes,
            });
            EXIT_OK
        }
        Err(error) => fail(&error),
    }
}

fn restore(args: RestoreArgs) -> u8 {
    match restore_case(&args.backup, &args.destination) {
        Ok(restored) => {
            output::emit_json(&RestoreOutput {
                case_id: restored.case_id,
                directory: native_path(&restored.directory).encoded(),
                schema_version: restored.schema_version,
                objects: restored.objects,
                manifests: restored.manifests,
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
