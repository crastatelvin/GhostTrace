//! Streaming copy, atomic publish, and interrupted-job recovery (P2.2).
//!
//! Protocol (plan Section 8):
//! 1. open the source with `O_NOFOLLOW` — a link is never followed;
//! 2. validate the object identity observed during traversal;
//! 3. stream the exact bytes once into a private staging file while hashing
//!    them (one fixed buffer, bounded memory);
//! 4. flush and sync the staging file;
//! 5. re-check source identity, size, and modification time;
//! 6. atomically rename into `objects/sha256/ab/<digest>` and sync the bucket;
//! 7. only then may the caller commit database references.
//!
//! A failure at any step removes the staging file and publishes nothing. A
//! crash between steps 6 and 7 leaves an unreferenced object: recovery
//! reports it (never deletes it) so the operator can adopt or quarantine it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capture::coverage::{
    CoverageOutcome, CoverageReason, CoverageStatus, CoverageSummary, coverage_batch, coverage_key,
};
use crate::capture::walker::{EntryKind, WalkedEntry, walk_root};
use crate::capture::{CaptureSpec, unix};
use crate::domain::case::{AcquisitionMethod, AcquisitionState};
use crate::domain::event::{Event, NamedEventTimeRef};
use crate::domain::path::NativePath;
use crate::domain::time::{EventTime, TimeSemantic};
use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::{StreamDigest, digest_reader, sha256_hex};
use crate::integrity::manifest::{
    MANIFEST_FORMAT, ManifestCoverage, ManifestObject, ManifestRoot, ManifestV1, manifest_object,
};
use crate::jobs::{JobCheckpoint, JobKind, JobState};
use crate::service::CaseSession;
use crate::storage::CaseLayout;
use crate::storage::read::CaseReader;
use crate::storage::writer::{Param, WriteBatch, WriteOp};

/// Free-space reserve kept clear while writing staging bytes.
pub const DEFAULT_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
/// Worker count ceiling; I/O bound, so more than four rarely helps (Section 9).
pub const MAX_COPY_WORKERS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyLimits {
    pub max_file_bytes: u64,
    pub reserve_bytes: u64,
    pub workers: usize,
}

impl CopyLimits {
    pub fn from_spec(spec: &CaptureSpec) -> Self {
        Self {
            max_file_bytes: spec.max_file_bytes,
            reserve_bytes: DEFAULT_RESERVE_BYTES,
            workers: default_workers(),
        }
    }
}

impl Default for CopyLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: u64::MAX,
            reserve_bytes: DEFAULT_RESERVE_BYTES,
            workers: default_workers(),
        }
    }
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(MAX_COPY_WORKERS)
}

/// Progress and cancellation shared with the UI/CLI while copying.
#[derive(Debug, Default)]
pub struct CopyProgress {
    pub bytes_copied: AtomicU64,
    pub objects_published: AtomicU64,
    pub cancelled: AtomicBool,
}

impl CopyProgress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation; an in-flight copy stops after its current chunk.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// One file the walker observed, ready to copy.
#[derive(Debug, Clone)]
pub struct CopyTask {
    pub root_index: usize,
    pub root_label: String,
    pub native_relative: NativePath,
    pub source: PathBuf,
    /// Identity observed during traversal (`dev:ino` on Unix).
    pub expected_identity: Option<String>,
    pub expected_size: u64,
    pub hardlink_alias: bool,
}

impl CopyTask {
    fn from_entry(
        root_index: usize,
        root_label: &str,
        root_path: &Path,
        entry: &WalkedEntry,
    ) -> Self {
        let relative = unix::native_to_path(&entry.native_relative);
        let source = if entry.native_relative.encoded().is_empty() {
            root_path.to_path_buf()
        } else {
            root_path.join(relative)
        };
        Self {
            root_index,
            root_label: root_label.to_string(),
            native_relative: entry.native_relative.clone(),
            source,
            expected_identity: entry.object_identity.clone(),
            expected_size: entry.size.unwrap_or(0),
            hardlink_alias: entry.hardlink_alias,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopyStatus {
    /// Bytes written, synced, re-checked, and renamed into the object store.
    Published,
    /// Identical content already present; staging was discarded.
    Deduplicated,
    /// Larger than the configured copy cap; recorded, never read.
    TooLarge,
    /// Source identity or metadata changed between observation and publish.
    Unstable,
    /// Source disappeared before or during the copy.
    Vanished,
    /// Permission or open failure (including a link where a file was expected).
    Inaccessible,
    /// The copy itself failed (write/sync error); nothing was published.
    Failed,
    /// Cancelled before the object was published.
    Cancelled,
}

impl CopyStatus {
    pub fn is_published(self) -> bool {
        matches!(self, CopyStatus::Published | CopyStatus::Deduplicated)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CopyStatus::Published => "published",
            CopyStatus::Deduplicated => "deduplicated",
            CopyStatus::TooLarge => "too_large",
            CopyStatus::Unstable => "unstable",
            CopyStatus::Vanished => "vanished",
            CopyStatus::Inaccessible => "inaccessible",
            CopyStatus::Failed => "failed",
            CopyStatus::Cancelled => "cancelled",
        }
    }
}

/// Result for one source path. `detail` is a stable code, never content.
#[derive(Debug, Clone)]
pub struct CopyOutcome {
    pub root_index: usize,
    pub root_label: String,
    pub native_relative: NativePath,
    pub status: CopyStatus,
    pub byte_length: u64,
    pub sha256: Option<[u8; 32]>,
    pub store_subpath: Option<String>,
    pub hardlink_alias: bool,
    /// Identity observed during traversal, scoped to this acquisition.
    pub object_identity: Option<String>,
    /// Source modification time (Unix seconds + nanos), when observable.
    pub modified_seconds: Option<i64>,
    pub modified_nanos: Option<u32>,
    pub detail: Option<&'static str>,
}

impl CopyOutcome {
    fn new(task: &CopyTask, status: CopyStatus, detail: Option<&'static str>) -> Self {
        Self {
            root_index: task.root_index,
            root_label: task.root_label.clone(),
            native_relative: task.native_relative.clone(),
            status,
            byte_length: 0,
            sha256: None,
            store_subpath: None,
            hardlink_alias: task.hardlink_alias,
            object_identity: task.expected_identity.clone(),
            modified_seconds: None,
            modified_nanos: None,
            detail,
        }
    }

    fn with_digest(
        task: &CopyTask,
        status: CopyStatus,
        digest: StreamDigest,
        store_subpath: String,
    ) -> Self {
        Self {
            byte_length: digest.byte_length,
            sha256: Some(digest.sha256),
            store_subpath: Some(store_subpath),
            ..Self::new(task, status, None)
        }
    }

    /// How this copy result feeds the coverage ledger.
    pub fn coverage(&self) -> (CoverageStatus, CoverageReason) {
        match self.status {
            CopyStatus::Published => (CoverageStatus::Captured, CoverageReason::Captured),
            CopyStatus::Deduplicated if self.hardlink_alias => (
                CoverageStatus::Captured,
                CoverageReason::DeduplicatedHardlink("same object identity".into()),
            ),
            CopyStatus::Deduplicated => (CoverageStatus::Captured, CoverageReason::Captured),
            CopyStatus::TooLarge => (
                CoverageStatus::Excluded,
                CoverageReason::PolicyExcluded("larger than the copy size cap".into()),
            ),
            CopyStatus::Unstable => (
                CoverageStatus::Unstable,
                CoverageReason::MetadataChanged(self.detail.unwrap_or("changed").into()),
            ),
            CopyStatus::Vanished => (
                CoverageStatus::Vanished,
                CoverageReason::Vanished(self.detail.unwrap_or("gone").into()),
            ),
            CopyStatus::Inaccessible => (
                CoverageStatus::Inaccessible,
                CoverageReason::OpenFailed(self.detail.unwrap_or("open failed").into()),
            ),
            CopyStatus::Failed => (
                CoverageStatus::Inaccessible,
                CoverageReason::OpenFailed(self.detail.unwrap_or("copy failed").into()),
            ),
            CopyStatus::Cancelled => (
                CoverageStatus::Unobserved,
                CoverageReason::TraversalLimited("cancelled before capture".into()),
            ),
        }
    }
}

/// Source metadata used for the pre/post recheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceStamp {
    pub identity: Option<String>,
    pub size: u64,
    pub modified: Option<std::time::SystemTime>,
}

/// Stamp of one open source descriptor (fstat, never follows).
pub fn stamp_of(file: &File) -> CoreResult<SourceStamp> {
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::Storage(format!("fstat: {error}")))?;
    Ok(SourceStamp {
        identity: identity_of(&metadata),
        size: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

/// Stamp of the path as it exists *now* (lstat). Used to detect replacement.
pub fn stamp_of_path(path: &Path) -> CoreResult<SourceStamp> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| CoreError::Storage(format!("lstat: {error}")))?;
    Ok(SourceStamp {
        identity: identity_of(&metadata),
        size: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

#[cfg(unix)]
fn identity_of(metadata: &std::fs::Metadata) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    Some(format!("{}:{}", metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn identity_of(_metadata: &std::fs::Metadata) -> Option<String> {
    None
}

/// Bytes available to this process on the filesystem holding `directory`.
// `libc::c_ulong` is 32-bit on some targets; the cast keeps the public type
// u64 everywhere, so it is intentional where clippy sees a no-op.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
pub fn available_bytes(directory: &Path) -> Option<u64> {
    nix::sys::statvfs::statvfs(directory)
        .ok()
        .map(|stats| (stats.blocks_available() as u64).saturating_mul(stats.fragment_size() as u64))
}

#[cfg(not(unix))]
pub fn available_bytes(_directory: &Path) -> Option<u64> {
    None
}

/// Refuse to start a copy that would eat into the free-space reserve.
pub fn ensure_reserve(directory: &Path, needed: u64, reserve: u64) -> CoreResult<()> {
    match available_bytes(directory) {
        Some(available) if available < needed.saturating_add(reserve) => {
            Err(CoreError::ResourceLimit)
        }
        _ => Ok(()),
    }
}

/// Copy one source file through staging to its content-addressed home.
pub fn copy_one(
    task: &CopyTask,
    layout: &CaseLayout,
    limits: &CopyLimits,
    progress: &CopyProgress,
) -> CoreResult<CopyOutcome> {
    if progress.is_cancelled() {
        return Ok(CopyOutcome::new(
            task,
            CopyStatus::Cancelled,
            Some("cancelled"),
        ));
    }
    let mut source = match open_source(&task.source) {
        Ok(file) => file,
        Err(error) => return Ok(open_failure_outcome(task, &error)),
    };
    let before = stamp_of(&source)?;
    if let Some(expected) = &task.expected_identity
        && before.identity.as_deref() != Some(expected.as_str())
    {
        return Ok(CopyOutcome::new(
            task,
            CopyStatus::Unstable,
            Some("identity_changed"),
        ));
    }
    if before.size > limits.max_file_bytes {
        return Ok(CopyOutcome::new(task, CopyStatus::TooLarge, None));
    }
    ensure_reserve(&layout.staging_root(), before.size, limits.reserve_bytes)?;

    let staging = layout
        .staging_root()
        .join(format!("{}.part", Uuid::new_v4()));
    let mut sink = create_staging(&staging)?;
    let digest = {
        let mut tee = Tee {
            source: &mut source,
            sink: &mut sink,
            progress,
        };
        match digest_reader(&mut tee, &progress.cancelled) {
            Ok(digest) => digest,
            Err(CoreError::Cancelled) => {
                remove_quietly(&staging);
                return Ok(CopyOutcome::new(
                    task,
                    CopyStatus::Cancelled,
                    Some("cancelled"),
                ));
            }
            Err(error) => {
                remove_quietly(&staging);
                return Err(error);
            }
        }
    };
    if let Err(error) = sink.sync_all() {
        remove_quietly(&staging);
        return Err(CoreError::Storage(format!("staging sync: {error}")));
    }
    drop(sink);

    // Source replacement and in-place modification are both detectable:
    // the descriptor stamp catches the latter, the path stamp the former.
    let (modified_seconds, modified_nanos) = unix_parts(before.modified);
    let after = stamp_of(&source)?;
    let path_now = match stamp_of_path(&task.source) {
        Ok(stamp) => stamp,
        Err(_) => {
            remove_quietly(&staging);
            return Ok(CopyOutcome::new(
                task,
                CopyStatus::Vanished,
                Some("vanished_during_capture"),
            ));
        }
    };
    if after != before || path_now.identity != before.identity || path_now.size != before.size {
        remove_quietly(&staging);
        return Ok(CopyOutcome::new(
            task,
            CopyStatus::Unstable,
            Some("changed_during_capture"),
        ));
    }

    let mut outcome = publish(task, &staging, digest, layout, progress)?;
    outcome.modified_seconds = modified_seconds;
    outcome.modified_nanos = modified_nanos;
    Ok(outcome)
}

fn unix_parts(time: Option<std::time::SystemTime>) -> (Option<i64>, Option<u32>) {
    match time.and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok()) {
        Some(elapsed) => (Some(elapsed.as_secs() as i64), Some(elapsed.subsec_nanos())),
        None => (None, None),
    }
}

fn publish(
    task: &CopyTask,
    staging: &Path,
    digest: StreamDigest,
    layout: &CaseLayout,
    progress: &CopyProgress,
) -> CoreResult<CopyOutcome> {
    let hex = sha256_hex(&digest.sha256);
    let bucket = &hex[..2];
    let directory = layout.objects_root().join(bucket);
    std::fs::create_dir_all(&directory)
        .map_err(|error| CoreError::Storage(format!("object bucket: {error}")))?;
    let target = directory.join(&hex);
    let store_subpath = format!("objects/sha256/{bucket}/{hex}");

    if target.exists() {
        let size = std::fs::metadata(&target)
            .map_err(|error| CoreError::Storage(format!("object stat: {error}")))?
            .len();
        if size != digest.byte_length {
            remove_quietly(staging);
            return Err(CoreError::CorruptEvidence);
        }
        remove_quietly(staging);
        return Ok(CopyOutcome::with_digest(
            task,
            CopyStatus::Deduplicated,
            digest,
            store_subpath,
        ));
    }

    std::fs::rename(staging, &target).map_err(|error| {
        remove_quietly(staging);
        CoreError::Storage(format!("object publish: {error}"))
    })?;
    sync_directory(&directory)?;
    progress.objects_published.fetch_add(1, Ordering::Relaxed);
    Ok(CopyOutcome::with_digest(
        task,
        CopyStatus::Published,
        digest,
        store_subpath,
    ))
}

/// Copy every task with a bounded worker pool. Cancellation leaves the
/// not-yet-started tasks as explicit `Cancelled` outcomes, never silence.
pub fn copy_all(
    tasks: Vec<CopyTask>,
    layout: &CaseLayout,
    limits: &CopyLimits,
    progress: &CopyProgress,
) -> CoreResult<Vec<CopyOutcome>> {
    if tasks.is_empty() {
        return Ok(Vec::new());
    }
    let workers = limits.workers.clamp(1, MAX_COPY_WORKERS).min(tasks.len());
    let queue = Mutex::new(tasks);
    let results: Mutex<Vec<CopyOutcome>> = Mutex::new(Vec::new());
    let failure: Mutex<Option<CoreError>> = Mutex::new(None);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    if progress.is_cancelled()
                        || failure
                            .lock()
                            .map(|failure| failure.is_some())
                            .unwrap_or(true)
                    {
                        break;
                    }
                    let task = queue.lock().ok().and_then(|mut queue| queue.pop());
                    let Some(task) = task else {
                        break;
                    };
                    match copy_one(&task, layout, limits, progress) {
                        Ok(outcome) => {
                            if let Ok(mut results) = results.lock() {
                                results.push(outcome);
                            }
                        }
                        Err(error) => {
                            if let Ok(mut failure) = failure.lock() {
                                *failure = Some(error);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });

    if let Ok(mut failure) = failure.lock()
        && let Some(error) = failure.take()
    {
        return Err(error);
    }
    let mut outcomes = results
        .into_inner()
        .map_err(|_| CoreError::Internal("copy results poisoned".into()))?;
    let remaining = queue
        .into_inner()
        .map_err(|_| CoreError::Internal("copy queue poisoned".into()))?;
    for task in remaining {
        outcomes.push(CopyOutcome::new(
            &task,
            CopyStatus::Cancelled,
            Some("cancelled"),
        ));
    }
    outcomes.sort_by(|left, right| {
        (left.root_index, left.native_relative.encoded())
            .cmp(&(right.root_index, right.native_relative.encoded()))
    });
    Ok(outcomes)
}

/// Options for one end-to-end acquisition.
#[derive(Debug, Clone)]
pub struct AcquisitionOptions {
    pub method: AcquisitionMethod,
    pub claimed_source: String,
    pub limits: CopyLimits,
}

impl AcquisitionOptions {
    pub fn new(
        method: AcquisitionMethod,
        claimed_source: impl Into<String>,
        spec: &CaptureSpec,
    ) -> Self {
        Self {
            method,
            claimed_source: claimed_source.into(),
            limits: CopyLimits::from_spec(spec),
        }
    }
}

/// Everything one acquisition did, in a form a front end can report.
#[derive(Debug, Clone)]
pub struct AcquisitionReport {
    pub acquisition_id: String,
    pub job_id: String,
    pub state: AcquisitionState,
    pub coverage: CoverageSummary,
    pub copies: Vec<CopyOutcome>,
    pub manifest: Option<ManifestV1>,
    pub manifest_path: Option<PathBuf>,
}

impl AcquisitionReport {
    pub fn published_objects(&self) -> usize {
        self.copies
            .iter()
            .filter(|copy| copy.status.is_published())
            .count()
    }
}

/// Run a validated capture: walk, copy/hash, publish, record coverage and
/// capture metadata, write the manifest, and settle the job state.
pub fn run_acquisition(
    session: &CaseSession,
    spec: &CaptureSpec,
    options: &AcquisitionOptions,
    progress: &CopyProgress,
) -> CoreResult<AcquisitionReport> {
    spec.validate().into_result()?;
    let created_seconds = now_seconds();
    let acquisition_id = format!("acq-{}", Uuid::new_v4());
    let job_id = format!("job-{}", Uuid::new_v4());
    let case_id = session.case_id().to_string();
    let tool_version = tool_version();

    let root_descriptors: Vec<ManifestRoot> = spec
        .roots
        .iter()
        .map(|root| ManifestRoot {
            label: root.label.clone(),
            native_path_encoded: root.native.encoded(),
        })
        .collect();
    let roots_json = serde_json::to_string(&root_descriptors)
        .map_err(|error| CoreError::Internal(format!("roots json: {error}")))?;

    // The acquisition exists before any bytes move: coverage and objects have
    // a parent row, and a crash leaves a resumable record.
    session
        .writer()
        .execute(WriteBatch::new().push(WriteOp::fact(
            "acquisitions",
            vec![
                "id",
                "case_id",
                "method",
                "claimed_source",
                "roots_json",
                "link_policy",
                "state",
                "started_seconds",
                "ended_seconds",
                "tool_version",
            ],
            vec![
                Param::Text(acquisition_id.clone()),
                Param::Text(case_id.clone()),
                Param::Text(method_name(options.method).to_string()),
                Param::Text(options.claimed_source.clone()),
                Param::Text(roots_json.clone()),
                Param::Text("no_follow".to_string()),
                Param::Text("running".to_string()),
                Param::Int(created_seconds),
                Param::OptInt(None),
                Param::Text(tool_version.clone()),
            ],
        )))?;

    let input_digest = sha256_hex(&sha256_bytes(roots_json.as_bytes()));
    let mut checkpoint = JobCheckpoint::queued(
        job_id.clone(),
        JobKind::Acquisition,
        format!("roots:{roots_json}"),
        input_digest,
    );
    checkpoint.state = JobState::Running;
    checkpoint.adapter_version = tool_version.clone();
    checkpoint.config_digest = format!("max_depth={}", spec.max_depth);
    checkpoint.updated_seconds = created_seconds;
    session.writer().queue_job_checkpoint(&checkpoint)?;

    // Walk every root, then copy its files.
    let mut tasks = Vec::new();
    let mut walked: Vec<(usize, CoverageOutcome)> = Vec::new();
    for (index, root) in spec.roots.iter().enumerate() {
        let outcome = walk_root(root, spec)?;
        let root_path = unix::native_to_path(&root.native);
        for entry in &outcome.entries {
            if entry.kind == EntryKind::File {
                tasks.push(CopyTask::from_entry(index, &root.label, &root_path, entry));
            }
        }
        for coverage in outcome.outcomes {
            walked.push((index, coverage));
        }
    }
    let copies = copy_all(tasks, session.layout(), &options.limits, progress)?;

    let mut copy_index: HashMap<(usize, String), &CopyOutcome> = HashMap::new();
    for copy in &copies {
        copy_index.insert((copy.root_index, copy.native_relative.encoded()), copy);
    }

    // Objects, observations, and merged coverage.
    let mut merged = CoverageSummary::new();
    let mut coverage_rows: Vec<(String, CoverageOutcome)> = Vec::new();
    let mut objects: Vec<ManifestObject> = Vec::new();
    let mut object_rows = WriteBatch::new();
    // Coverage key -> the object and exact encoded path it describes, so each
    // event can point at its own source without re-deriving anything.
    let mut event_sources: BTreeMap<String, (String, String)> = BTreeMap::new();
    let observed_at = created_seconds;

    for (root_index, walked_outcome) in &walked {
        let root = &spec.roots[*root_index];
        let root_encoded = root.native.encoded();
        let merged_outcome =
            match copy_index.get(&(*root_index, walked_outcome.native_relative.encoded())) {
                Some(copy) => {
                    let (status, reason) = copy.coverage();
                    let mut outcome = walked_outcome.clone();
                    outcome.status = status;
                    outcome.reason = reason;
                    outcome
                }
                None => walked_outcome.clone(),
            };
        if let Some(copy) = copy_index.get(&(*root_index, walked_outcome.native_relative.encoded()))
            && copy.status.is_published()
        {
            let digest = StreamDigest {
                byte_length: copy.byte_length,
                sha256: copy.sha256.expect("published copy carries a digest"),
            };
            let object_id = format!("obj-{}", Uuid::new_v4());
            let store_subpath = copy.store_subpath.clone().unwrap_or_default();
            event_sources.insert(
                coverage_key(&root_encoded, &merged_outcome),
                (object_id.clone(), copy.native_relative.encoded()),
            );
            object_rows = object_rows
                .push(WriteOp::fact(
                    "evidence_objects",
                    vec![
                        "id",
                        "acquisition_id",
                        "native_path_kind",
                        "native_path_encoded",
                        "kind",
                        "byte_length",
                        "digest_status",
                        "sha256",
                        "object_location",
                    ],
                    vec![
                        Param::Text(object_id.clone()),
                        Param::Text(acquisition_id.clone()),
                        Param::Text(path_kind().to_string()),
                        Param::Text(copy.native_relative.encoded()),
                        Param::Text("file_content".to_string()),
                        Param::Int(digest.byte_length as i64),
                        Param::Text("complete".to_string()),
                        Param::Bytes(digest.sha256.to_vec()),
                        Param::Text(store_subpath.clone()),
                    ],
                ))
                .push(WriteOp::fact(
                    "file_observations",
                    vec![
                        "id",
                        "acquisition_id",
                        "evidence_id",
                        "scoped_identity",
                        "size",
                        "link_target_encoded",
                        "link_target_kind",
                        "observed_seconds",
                        "observed_nanos",
                        "source_mtime_seconds",
                        "source_mtime_nanos",
                    ],
                    vec![
                        Param::Text(format!("obs-{}", Uuid::new_v4())),
                        Param::Text(acquisition_id.clone()),
                        Param::Text(object_id.clone()),
                        Param::OptText(copy.object_identity.clone()),
                        Param::Int(digest.byte_length as i64),
                        Param::OptText(None),
                        Param::OptText(None),
                        Param::Int(observed_at),
                        Param::Int(0),
                        Param::OptInt(copy.modified_seconds),
                        Param::OptInt(copy.modified_nanos.map(i64::from)),
                    ],
                ));
            objects.push(manifest_object(
                object_id,
                copy.root_label.clone(),
                copy.native_relative.encoded(),
                digest,
                store_subpath,
                copy.hardlink_alias,
            ));
        }
        merged.record(merged_outcome.clone());
        coverage_rows.push((coverage_key(&root_encoded, &merged_outcome), merged_outcome));
    }

    session.writer().execute(object_rows)?;
    session
        .writer()
        .execute(coverage_batch(&acquisition_id, &coverage_rows)?)?;

    // Captured metadata events: the application clock instant at which the
    // tool observed each entry. Source timestamps belong to parsers (P4+).
    let parse_run_id = format!("run-{}", Uuid::new_v4());
    let revision = "r1";
    let mut parse_batch = WriteBatch::new().push(WriteOp::fact(
        "parse_runs",
        vec![
            "id",
            "acquisition_id",
            "parser_id",
            "parser_version",
            "config_digest",
            "state",
            "counts_json",
            "diagnostics_json",
        ],
        vec![
            Param::Text(parse_run_id.clone()),
            Param::Text(acquisition_id.clone()),
            Param::Text("capture.metadata.v1".to_string()),
            Param::Text(tool_version.clone()),
            Param::Text(String::new()),
            Param::Text("completed".to_string()),
            Param::Text(format!("{{\"entries\":{}}}", coverage_rows.len())),
            Param::Text("[]".to_string()),
        ],
    ));
    for (key, outcome) in &coverage_rows {
        let size = match outcome.status {
            CoverageStatus::Captured => "content",
            _ => "metadata",
        };
        let event = Event {
            id: format!("evt-{}", Uuid::new_v4()),
            kind: "file.observed".to_string(),
            summary: format!("filesystem entry observed ({size})"),
            observations: Vec::new(),
            times: vec![NamedEventTimeRef {
                name: "observed_at".to_string(),
                semantic: TimeSemantic::OccurrenceTime,
                value: EventTime::from_unix_seconds(observed_at, TimeSemantic::OccurrenceTime),
            }],
            host_claim: None,
            revision: parse_run_id.clone(),
        };
        parse_batch = parse_batch.push(WriteOp::fact(
            "events",
            vec![
                "id",
                "revision",
                "parse_run_id",
                "kind",
                "summary",
                "host_claim",
                "chosen_seconds",
                "chosen_nanos",
                "time_status",
                "evidence_id",
                "locator_identity",
            ],
            vec![
                Param::Text(event.id.clone()),
                Param::Text(revision.to_string()),
                Param::Text(parse_run_id.clone()),
                Param::Text(event.kind.clone()),
                Param::Text(event.summary.clone()),
                Param::OptText(None),
                Param::Int(observed_at),
                Param::Int(0),
                Param::Text("resolved".to_string()),
                Param::OptText(event_sources.get(key).map(|source| source.0.clone())),
                Param::OptText(event_sources.get(key).map(|source| source.1.clone())),
            ],
        ));
        parse_batch = parse_batch.push(WriteOp::fact(
            "event_times",
            vec![
                "event_id",
                "name",
                "semantic",
                "status",
                "candidates_json",
                "raw_field",
                "raw_value_kind",
                "raw_value_text",
                "raw_text",
                "epoch",
                "unit",
                "declared_precision",
                "clock_domain",
                "assumptions_json",
            ],
            vec![
                Param::Text(event.id),
                Param::Text("observed_at".to_string()),
                Param::Text("occurrence_time".to_string()),
                Param::Text("resolved".to_string()),
                Param::Text(format!("[{observed_at}]")),
                Param::OptText(None),
                Param::OptText(None),
                Param::OptText(None),
                Param::OptText(None),
                Param::Text("unix".to_string()),
                Param::Text("seconds".to_string()),
                Param::Text("seconds".to_string()),
                Param::Text("host".to_string()),
                Param::Text("[]".to_string()),
            ],
        ));
    }
    session.writer().execute(parse_batch)?;

    let copy_gap = copies.iter().any(|copy| !copy.status.is_published());
    let ledger_gap =
        merged.inaccessible + merged.unstable + merged.vanished + merged.unobserved > 0;
    let state = if progress.is_cancelled() {
        AcquisitionState::Cancelled
    } else if copy_gap || ledger_gap {
        AcquisitionState::Partial
    } else {
        AcquisitionState::Completed
    };

    // Manifest: written before the final state commit, atomically.
    let manifest = ManifestV1 {
        format: MANIFEST_FORMAT.to_string(),
        manifest_id: format!("manifest-{acquisition_id}"),
        case_id: case_id.clone(),
        acquisition_id: acquisition_id.clone(),
        method: method_name(options.method).to_string(),
        tool_version: tool_version.clone(),
        created_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        link_policy: "no_follow".to_string(),
        roots: root_descriptors,
        coverage: ManifestCoverage {
            captured: merged.captured,
            excluded: merged.excluded,
            inaccessible: merged.inaccessible,
            unstable: merged.unstable,
            vanished: merged.vanished,
            unsupported: merged.unsupported,
            unobserved: merged.unobserved,
            hardlink_aliases: merged.hardlink_aliases,
        },
        objects,
    };
    let manifest_path = if state == AcquisitionState::Cancelled {
        None
    } else {
        Some(manifest.write_atomic(&session.layout().manifests_root())?)
    };

    let ended_seconds = now_seconds();
    let counters = format!(
        "{{\"objects\":{},\"bytes\":{},\"captured\":{},\"gaps\":{}}}",
        manifest.objects.len(),
        manifest
            .objects
            .iter()
            .map(|object| object.byte_length)
            .sum::<u64>(),
        merged.captured,
        merged.gaps()
    );
    session
        .writer()
        .execute(WriteBatch::new().push(WriteOp::upsert(
            "acquisitions",
            vec![
                "id",
                "case_id",
                "method",
                "claimed_source",
                "roots_json",
                "link_policy",
                "state",
                "started_seconds",
                "ended_seconds",
                "tool_version",
            ],
            vec![
                Param::Text(acquisition_id.clone()),
                Param::Text(case_id),
                Param::Text(method_name(options.method).to_string()),
                Param::Text(options.claimed_source.clone()),
                Param::Text(roots_json),
                Param::Text("no_follow".to_string()),
                Param::Text(state_name(state).to_string()),
                Param::Int(created_seconds),
                Param::OptInt(Some(ended_seconds)),
                Param::Text(tool_version),
            ],
        )))?;
    checkpoint.state = match state {
        AcquisitionState::Completed => JobState::Completed,
        AcquisitionState::Partial => JobState::Partial,
        AcquisitionState::Cancelled => JobState::Cancelled,
        AcquisitionState::Failed => JobState::Failed,
        AcquisitionState::Queued | AcquisitionState::Running => JobState::Running,
    };
    checkpoint.committed_locator = manifest_path
        .as_ref()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .map(str::to_string);
    checkpoint.counters_json = counters;
    checkpoint.updated_seconds = ended_seconds;
    session.writer().queue_job_checkpoint(&checkpoint)?;

    Ok(AcquisitionReport {
        acquisition_id,
        job_id,
        state,
        coverage: merged,
        copies,
        manifest: Some(manifest),
        manifest_path,
    })
}

/// One recovered item: our own incomplete staging or a published-but-
/// unreferenced object. Nothing is deleted by inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanObject {
    pub store_subpath: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub abandoned_staging: Vec<String>,
    pub orphan_objects: Vec<OrphanObject>,
}

impl RecoveryReport {
    pub fn is_empty(&self) -> bool {
        self.abandoned_staging.is_empty() && self.orphan_objects.is_empty()
    }
}

/// Inspect the case for interrupted-copy leftovers. A crash after the object
/// rename but before the database commit leaves an orphan here; the operator
/// can adopt it with an explicit recovery action, never by silent deletion.
pub fn inspect_recovery(layout: &CaseLayout, reader: &CaseReader) -> CoreResult<RecoveryReport> {
    let mut abandoned_staging = Vec::new();
    if let Ok(entries) = std::fs::read_dir(layout.staging_root()) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && name.ends_with(".part")
            {
                abandoned_staging.push(name.to_string());
            }
        }
    }
    abandoned_staging.sort();

    let mut referenced: HashSet<String> = HashSet::new();
    let mut statement = reader
        .connection()
        .prepare("SELECT object_location FROM evidence_objects WHERE object_location IS NOT NULL")
        .map_err(|error| CoreError::Storage(format!("recovery query: {error}")))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| CoreError::Storage(format!("recovery query: {error}")))?;
    for row in rows {
        referenced
            .insert(row.map_err(|error| CoreError::Storage(format!("recovery row: {error}")))?);
    }

    let mut orphan_objects = Vec::new();
    let objects_root = layout.objects_root();
    if let Ok(buckets) = std::fs::read_dir(&objects_root) {
        for bucket in buckets.flatten() {
            let bucket_name = bucket.file_name().to_string_lossy().to_string();
            let Ok(files) = std::fs::read_dir(bucket.path()) else {
                continue;
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().to_string();
                let store_subpath = format!("objects/sha256/{bucket_name}/{name}");
                if referenced.contains(&store_subpath) {
                    continue;
                }
                let byte_length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
                orphan_objects.push(OrphanObject {
                    store_subpath,
                    byte_length,
                });
            }
        }
    }
    orphan_objects.sort_by(|left, right| left.store_subpath.cmp(&right.store_subpath));

    Ok(RecoveryReport {
        abandoned_staging,
        orphan_objects,
    })
}

/// Read the tool version once, so the manifest and rows agree.
pub fn tool_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let never = AtomicBool::new(false);
    let mut reader = bytes;
    digest_reader(&mut reader, &never)
        .map(|digest| digest.sha256)
        .unwrap_or([0u8; 32])
}

fn method_name(method: AcquisitionMethod) -> &'static str {
    match method {
        AcquisitionMethod::ProtectedCopy => "protected_copy",
        AcquisitionMethod::LiveBestEffort => "live_best_effort",
    }
}

fn state_name(state: AcquisitionState) -> &'static str {
    match state {
        AcquisitionState::Queued => "queued",
        AcquisitionState::Running => "running",
        AcquisitionState::Completed => "completed",
        AcquisitionState::Partial => "partial",
        AcquisitionState::Cancelled => "cancelled",
        AcquisitionState::Failed => "failed",
    }
}

#[cfg(unix)]
fn path_kind() -> &'static str {
    "unix"
}

#[cfg(not(unix))]
fn path_kind() -> &'static str {
    "windows"
}

/// Open the source without following links and without blocking on a FIFO.
#[cfg(unix)]
fn open_source(path: &Path) -> std::io::Result<File> {
    use nix::fcntl::OFlag;
    let fd = nix::fcntl::open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
    Ok(File::from(fd))
}

#[cfg(not(unix))]
fn open_source(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn open_failure_outcome(task: &CopyTask, error: &std::io::Error) -> CopyOutcome {
    let status = match error.kind() {
        std::io::ErrorKind::NotFound => CopyStatus::Vanished,
        std::io::ErrorKind::PermissionDenied => CopyStatus::Inaccessible,
        _ if is_symlink_error(error) => CopyStatus::Inaccessible,
        _ => CopyStatus::Inaccessible,
    };
    let detail = if is_symlink_error(error) {
        "symlink_not_followed"
    } else if status == CopyStatus::Vanished {
        "vanished_before_open"
    } else {
        "open_failed"
    };
    CopyOutcome::new(task, status, Some(detail))
}

fn is_symlink_error(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// Private staging file: exclusive create, owner-only permissions.
fn create_staging(path: &Path) -> CoreResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| CoreError::Storage(format!("staging create: {error}")))
}

fn remove_quietly(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn sync_directory(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| CoreError::Storage(format!("sync dir: {error}")))?;
    }
    Ok(())
}

/// Read-through tee: every byte hashed is also the byte written.
struct Tee<'a, R: Read, W: Write> {
    source: &'a mut R,
    sink: &'a mut W,
    progress: &'a CopyProgress,
}

impl<R: Read, W: Write> Read for Tee<'_, R, W> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.source.read(buffer)?;
        if read > 0 {
            self.sink.write_all(&buffer[..read])?;
            self.progress
                .bytes_copied
                .fetch_add(read as u64, Ordering::Relaxed);
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_produces_explicit_outcomes() {
        let progress = CopyProgress::new();
        progress.cancel();
        let outcome = CopyOutcome::new(
            &CopyTask {
                root_index: 0,
                root_label: "root".into(),
                native_relative: NativePath::unix("a.txt"),
                source: PathBuf::from("/nonexistent"),
                expected_identity: None,
                expected_size: 0,
                hardlink_alias: false,
            },
            CopyStatus::Cancelled,
            Some("cancelled"),
        );
        let (status, reason) = outcome.coverage();
        assert_eq!(status, CoverageStatus::Unobserved);
        assert_eq!(reason.code(), "traversal_limited");
        assert!(!status.is_captured());
    }

    #[cfg(unix)]
    #[test]
    fn source_stamp_tracks_size_and_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.txt");
        std::fs::write(&path, b"one").unwrap();
        let file = File::open(&path).unwrap();
        let before = stamp_of(&file).unwrap();
        drop(file);

        // Same inode, same size, newer mtime: still a change.
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(3).unwrap();
        let stamp = nix::sys::time::TimeSpec::new(1, 0);
        nix::sys::stat::utimensat(
            nix::fcntl::AT_FDCWD,
            &path,
            &stamp,
            &stamp,
            nix::sys::stat::UtimensatFlags::FollowSymlink,
        )
        .unwrap();
        let after = stamp_of(&file).unwrap();
        assert_ne!(before, after, "mtime change must be visible");
        assert_eq!(before.identity, after.identity);
    }
}
