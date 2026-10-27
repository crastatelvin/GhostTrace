//! The one dedicated writer per case (plan Sections 8, 17/P1.2).
//!
//! Ownership: a single background thread owns the write `Connection`; callers
//! never touch it directly. Batches travel over a **bounded** channel
//! (`sync_channel`), so a saturated writer applies backpressure instead of
//! buffering unbounded work. Every batch executes in one transaction: an
//! interruption (foreign-key violation, unique conflict, I/O error) rolls the
//! whole batch back — half a batch is never visible.
//!
//! Cross-process note: SQLite WAL write locks still serialize concurrent
//! writers, but a second *writer* for the same case is an application bug and
//! fails fast here within the process.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::sync_channel;
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::Connection;

use crate::domain;
use crate::error::{CoreError, CoreResult};
use crate::jobs::JobCheckpoint;

/// Measured busy timeout: parses and captures across busy disks may stall a
/// WAL writer briefly; 5s was chosen for P1.2 and is recorded in diagnostics.
const BUSY_TIMEOUT_MS: u64 = 5_000;
/// Bounded queue depth for write batches.
const DEFAULT_QUEUE_DEPTH: usize = 64;

fn open_writers() -> &'static Mutex<HashSet<PathBuf>> {
    static OPEN_WRITERS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    OPEN_WRITERS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// One stored value for a single-row write operation.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    OptInt(Option<i64>),
    OptText(Option<String>),
}

impl Param {
    fn bind(
        &self,
        statement: &mut rusqlite::Statement<'_>,
        position: usize,
    ) -> rusqlite::Result<()> {
        match self {
            Param::Int(value) => statement.raw_bind_parameter(position, *value)?,
            Param::Text(value) => statement.raw_bind_parameter(position, value.as_str())?,
            Param::Bytes(value) => statement.raw_bind_parameter(position, value.as_slice())?,
            Param::OptInt(value) => statement.raw_bind_parameter(position, *value)?,
            Param::OptText(value) => statement.raw_bind_parameter(position, value.as_deref())?,
        }
        Ok(())
    }
}

/// Idempotency policy for a single-row write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    /// Facts are never destroyed: an existing row wins (replays are no-ops).
    Ignore,
    /// Checkpoints are mutable state and must be updatable.
    Replace,
}

/// A single-row insert/upsert against one table.
#[derive(Debug, Clone)]
pub struct WriteOp {
    pub table: &'static str,
    pub columns: Vec<&'static str>,
    pub values: Vec<Param>,
    pub conflict: ConflictPolicy,
}

impl WriteOp {
    /// Build a single-row insert with the ignore policy (fact replay).
    pub fn fact(table: &'static str, columns: Vec<&'static str>, values: Vec<Param>) -> Self {
        Self {
            table,
            columns,
            values,
            conflict: ConflictPolicy::Ignore,
        }
    }

    /// Build a single-row upsert (mutable job checkpoints).
    pub fn upsert(table: &'static str, columns: Vec<&'static str>, values: Vec<Param>) -> Self {
        Self {
            table,
            columns,
            values,
            conflict: ConflictPolicy::Replace,
        }
    }

    fn sql(&self) -> String {
        let placeholders: Vec<String> = (1..=self.values.len()).map(|i| format!("?{i}")).collect();
        let conflict = match self.conflict {
            ConflictPolicy::Ignore => "ON CONFLICT DO NOTHING".to_string(),
            ConflictPolicy::Replace => {
                let updates: Vec<String> = self
                    .columns
                    .iter()
                    .map(|column| format!("{column} = excluded.{column}"))
                    .collect();
                format!("ON CONFLICT DO UPDATE SET {}", updates.join(", "))
            }
        };
        format!(
            "INSERT INTO {} ({}) VALUES ({}) {}",
            self.table,
            self.columns.join(", "),
            placeholders.join(", "),
            conflict,
        )
    }
}

/// One atomic unit of work. All ops commit together or not at all.
#[derive(Debug, Clone, Default)]
pub struct WriteBatch {
    pub ops: Vec<WriteOp>,
}

impl WriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(mut self, op: WriteOp) -> Self {
        self.ops.push(op);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Outcome of one committed batch. Idempotent replays report zero changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchResult {
    pub attempted: usize,
    pub applied: usize,
}

enum WriterCommand {
    Execute {
        batch: WriteBatch,
        reply: std::sync::mpsc::Sender<CoreResult<BatchResult>>,
    },
    Shutdown {
        reply: std::sync::mpsc::Sender<CoreResult<()>>,
    },
}

/// Handle to the dedicated writer thread. Cheap to clone is deliberately not
/// supported: one handle per case per process, matching ownership.
pub struct CaseWriter {
    database_path: PathBuf,
    commands: std::sync::mpsc::SyncSender<WriterCommand>,
    thread: Mutex<Option<JoinHandle<()>>>,
    queue_depth: usize,
}

impl CaseWriter {
    /// Spawn the writer thread for a case database. Rejects a second writer
    /// for the same database in this process.
    pub fn spawn(database_path: impl AsRef<Path>) -> CoreResult<Self> {
        Self::spawn_with_queue(database_path, DEFAULT_QUEUE_DEPTH)
    }

    pub fn spawn_with_queue(
        database_path: impl AsRef<Path>,
        queue_depth: usize,
    ) -> CoreResult<Self> {
        let database_path = database_path.as_ref().to_path_buf();
        let canonical = database_path
            .canonicalize()
            .unwrap_or_else(|_| database_path.clone());
        {
            let mut open = open_writers()
                .lock()
                .map_err(|_| CoreError::Internal("writer registry poisoned".into()))?;
            if !open.insert(canonical.clone()) {
                return Err(CoreError::Storage(
                    "another writer already owns this case in this process".into(),
                ));
            }
        }

        let owned_path = database_path.clone();
        let (commands, receiver) = sync_channel(queue_depth);
        let thread = std::thread::Builder::new()
            .name("ghosttrace-case-writer".into())
            .spawn(move || writer_loop(&owned_path, receiver))
            .map_err(|e| {
                release_writer(&canonical);
                CoreError::Storage(format!("cannot start writer thread: {e}"))
            })?;

        // Fail fast if the writer could not open its connection.
        let (open_reply, open_rx) = std::sync::mpsc::channel();
        if commands
            .send(WriterCommand::Execute {
                batch: WriteBatch::new(),
                reply: open_reply,
            })
            .is_err()
        {
            return Err(CoreError::Storage("writer thread did not start".into()));
        }
        match open_rx.recv() {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                let _ = join_writer(&commands, thread);
                release_writer(&canonical);
                return Err(error);
            }
            Err(_) => {
                release_writer(&canonical);
                return Err(CoreError::Storage(
                    "writer thread stopped unexpectedly".into(),
                ));
            }
        }

        Ok(Self {
            database_path,
            commands,
            thread: Mutex::new(Some(thread)),
            queue_depth,
        })
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn queue_depth(&self) -> usize {
        self.queue_depth
    }

    /// Submit one batch and wait for the commit result. A bounded-queue
    /// overflow blocks the caller (backpressure), never drops work.
    pub fn execute(&self, batch: WriteBatch) -> CoreResult<BatchResult> {
        if batch.is_empty() {
            return Ok(BatchResult {
                attempted: 0,
                applied: 0,
            });
        }
        let (reply, receiver) = std::sync::mpsc::channel();
        self.commands
            .send(WriterCommand::Execute { batch, reply })
            .map_err(|_| CoreError::Storage("writer thread is gone".into()))?;
        receiver
            .recv()
            .map_err(|_| CoreError::Storage("writer thread did not respond".into()))?
    }

    /// Queue a job checkpoint state (queued/running/completed/...).
    pub fn queue_job_checkpoint(&self, checkpoint: &JobCheckpoint) -> CoreResult<BatchResult> {
        self.execute(WriteBatch::new().push(WriteOp::upsert(
            "job_checkpoints",
            vec![
                "job_id",
                "kind",
                "state",
                "input_identity",
                "input_digest",
                "adapter_version",
                "config_digest",
                "committed_locator",
                "counters_json",
                "updated_seconds",
            ],
            vec![
                Param::Text(checkpoint.job_id.clone()),
                Param::Text(checkpoint.kind.as_str().to_string()),
                Param::Text(job_state_name(checkpoint.state).to_string()),
                Param::Text(checkpoint.input_identity.clone()),
                Param::Text(checkpoint.input_digest.clone()),
                Param::Text(checkpoint.adapter_version.clone()),
                Param::Text(checkpoint.config_digest.clone()),
                Param::OptText(checkpoint.committed_locator.clone()),
                Param::Text(checkpoint.counters_json.clone()),
                Param::Int(checkpoint.updated_seconds),
            ],
        )))
    }

    /// Queue one normalized event with its exact times. The chosen display
    /// instant is the earliest candidate of the primary time; an unresolved
    /// event keeps NULL chosen time and reaches the explicit unresolved view.
    pub fn queue_event(
        &self,
        event: &domain::event::Event,
        revision: &str,
    ) -> CoreResult<BatchResult> {
        self.execute(WriteBatch {
            ops: event_ops(event, revision)?,
        })
    }

    /// Create or update a parse run row (state, counts, diagnostics).
    pub fn queue_parse_run(&self, run: &ParseRunRecord) -> CoreResult<BatchResult> {
        self.execute(WriteBatch::new().push(parse_run_op(run)))
    }

    /// Commit one bounded import batch: the run row, raw observations, and
    /// normalized events. Facts replay idempotently.
    pub fn queue_import_batch(
        &self,
        run: &ParseRunRecord,
        observations: &[ObservationRecord],
        events: &[domain::event::Event],
        revision: &str,
    ) -> CoreResult<BatchResult> {
        let mut batch = WriteBatch::new().push(parse_run_op(run));
        for observation in observations {
            batch = batch.push(WriteOp::fact(
                "raw_observations",
                vec![
                    "id",
                    "parse_run_id",
                    "acquisition_id",
                    "evidence_id",
                    "locator_kind",
                    "locator_identity",
                    "raw_fields_json",
                ],
                vec![
                    Param::Text(observation.id.clone()),
                    Param::Text(observation.parse_run_id.clone()),
                    Param::Text(observation.acquisition_id.clone()),
                    Param::Text(observation.evidence_id.clone()),
                    Param::Text(observation.locator_kind.to_string()),
                    Param::Text(observation.locator_identity.clone()),
                    Param::Text(observation.raw_fields_json.clone()),
                ],
            ));
        }
        for event in events {
            batch.ops.extend(event_ops(event, revision)?);
        }
        self.execute(batch)
    }
}

/// A parse run as stored (plan Section 8: versioned, replayable runs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRunRecord {
    pub id: String,
    pub acquisition_id: String,
    pub parser_id: String,
    pub parser_version: String,
    pub config_digest: String,
    pub state: String,
    pub counts_json: String,
    pub diagnostics_json: String,
}

/// One extracted record before interpretation, keyed by its exact locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRecord {
    pub id: String,
    pub parse_run_id: String,
    pub acquisition_id: String,
    pub evidence_id: String,
    pub locator_kind: &'static str,
    pub locator_identity: String,
    pub raw_fields_json: String,
}

fn parse_run_op(run: &ParseRunRecord) -> WriteOp {
    WriteOp::upsert(
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
            Param::Text(run.id.clone()),
            Param::Text(run.acquisition_id.clone()),
            Param::Text(run.parser_id.clone()),
            Param::Text(run.parser_version.clone()),
            Param::Text(run.config_digest.clone()),
            Param::Text(run.state.clone()),
            Param::Text(run.counts_json.clone()),
            Param::Text(run.diagnostics_json.clone()),
        ],
    )
}

/// Build the row operations for one event and its times.
fn event_ops(event: &domain::event::Event, revision: &str) -> CoreResult<Vec<WriteOp>> {
    let primary = event.times.first();
    let chosen: Option<domain::time::UnixTime> =
        primary.and_then(|named| named.value.candidates.first().copied());
    let status = match primary {
        Some(named) => time_status_name(&named.value.status).to_string(),
        None => "unresolved".to_string(),
    };
    let mut ops = vec![WriteOp::fact(
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
        ],
        vec![
            Param::Text(event.id.clone()),
            Param::Text(revision.to_string()),
            Param::Text(event.revision.clone()),
            Param::Text(event.kind.clone()),
            Param::Text(event.summary.clone()),
            Param::OptText(event.host_claim.clone()),
            Param::OptInt(chosen.map(|instant| instant.seconds)),
            Param::Int(chosen.map_or(0, |instant| i64::from(instant.nanos))),
            Param::Text(status),
        ],
    )];
    for named in &event.times {
        let time = &named.value;
        let candidates_json = serde_json::to_string(&time.candidates)
            .map_err(|e| CoreError::Storage(format!("serialize candidates: {e}")))?;
        let assumptions_json = serde_json::to_string(&time.assumptions)
            .map_err(|e| CoreError::Storage(format!("serialize assumptions: {e}")))?;
        let raw = time.raw.as_ref();
        let (raw_value_text, raw_text, epoch, unit, precision) = match raw {
            Some(raw) => (
                raw.integer.map(|value| value.to_string()),
                raw.text.clone(),
                epoch_name(raw.epoch).to_string(),
                unit_name(raw.unit).to_string(),
                precision_name(raw.declared_precision).to_string(),
            ),
            None => (
                None,
                None,
                "unix".into(),
                "seconds".into(),
                "unknown".into(),
            ),
        };
        ops.push(WriteOp::fact(
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
                Param::Text(event.id.clone()),
                Param::Text(named.name.clone()),
                Param::Text(semantic_name(&time.semantic).to_string()),
                Param::Text(time_status_name(&time.status).to_string()),
                Param::Text(candidates_json),
                Param::OptText(raw.map(|raw| raw.field.clone())),
                Param::OptText(
                    raw.and_then(|raw| match (raw.integer, &raw.text) {
                        (Some(_), _) => Some("integer"),
                        (None, Some(_)) => Some("text"),
                        (None, None) => None,
                    })
                    .map(str::to_string),
                ),
                Param::OptText(raw_value_text),
                Param::OptText(raw_text),
                Param::Text(epoch),
                Param::Text(unit),
                Param::Text(precision),
                Param::Text(clock_domain_name(&time.clock_domain)),
                Param::Text(assumptions_json),
            ],
        ));
    }
    Ok(ops)
}

impl CaseWriter {
    pub fn shutdown(&self) -> CoreResult<()> {
        let (reply, receiver) = std::sync::mpsc::channel();
        if self
            .commands
            .send(WriterCommand::Shutdown { reply })
            .is_err()
        {
            return Ok(()); // already stopped
        }
        receiver
            .recv()
            .map_err(|_| CoreError::Storage("writer thread did not stop".into()))?
    }
}

impl Drop for CaseWriter {
    fn drop(&mut self) {
        let _ = self.shutdown();
        if let Ok(mut thread) = self.thread.lock()
            && let Some(handle) = thread.take()
        {
            let _ = handle.join();
        }
        release_writer(&self.database_path);
    }
}

fn release_writer(path: &Path) {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if let Ok(mut open) = open_writers().lock() {
        open.remove(&canonical);
    }
}

fn join_writer(
    commands: &std::sync::mpsc::SyncSender<WriterCommand>,
    thread: JoinHandle<()>,
) -> Result<(), CoreError> {
    let (reply, receiver) = std::sync::mpsc::channel();
    if commands.send(WriterCommand::Shutdown { reply }).is_ok() && receiver.recv().is_ok() {
        let _ = thread.join();
        Ok(())
    } else {
        Err(CoreError::Storage("writer thread did not stop".into()))
    }
}

fn job_state_name(state: crate::jobs::JobState) -> &'static str {
    match state {
        crate::jobs::JobState::Queued => "queued",
        crate::jobs::JobState::Running => "running",
        crate::jobs::JobState::Completed => "completed",
        crate::jobs::JobState::Partial => "partial",
        crate::jobs::JobState::Cancelled => "cancelled",
        crate::jobs::JobState::Failed => "failed",
    }
}

fn time_status_name(status: &domain::time::TimeStatus) -> &'static str {
    match status {
        domain::time::TimeStatus::Resolved => "resolved",
        domain::time::TimeStatus::Ambiguous => "ambiguous",
        domain::time::TimeStatus::Unresolved => "unresolved",
        domain::time::TimeStatus::Invalid => "invalid",
    }
}

fn epoch_name(epoch: domain::time::Epoch) -> &'static str {
    match epoch {
        domain::time::Epoch::Unix => "unix",
        domain::time::Epoch::WindowsFileTime1601 => "windows_filetime_1601",
        domain::time::Epoch::Chrome1601 => "chrome_1601",
        domain::time::Epoch::MacAbsolute2001 => "mac_absolute_2001",
    }
}

fn unit_name(unit: domain::time::TimeUnit) -> &'static str {
    match unit {
        domain::time::TimeUnit::Seconds => "seconds",
        domain::time::TimeUnit::Millis => "millis",
        domain::time::TimeUnit::Micros => "micros",
        domain::time::TimeUnit::Nanos => "nanos",
        domain::time::TimeUnit::Ticks100Ns => "ticks_100ns",
    }
}

fn precision_name(precision: domain::time::TimePrecision) -> &'static str {
    match precision {
        domain::time::TimePrecision::Nanos => "nanos",
        domain::time::TimePrecision::Micros => "micros",
        domain::time::TimePrecision::Millis => "millis",
        domain::time::TimePrecision::Seconds => "seconds",
        domain::time::TimePrecision::Minutes => "minutes",
        domain::time::TimePrecision::Unknown => "unknown",
    }
}

fn semantic_name(semantic: &domain::time::TimeSemantic) -> String {
    match semantic {
        domain::time::TimeSemantic::ContentModified => "content_modified".into(),
        domain::time::TimeSemantic::StatusChanged => "status_changed".into(),
        domain::time::TimeSemantic::Created => "created".into(),
        domain::time::TimeSemantic::Accessed => "accessed".into(),
        domain::time::TimeSemantic::LoggedTime => "logged_time".into(),
        domain::time::TimeSemantic::OccurrenceTime => "occurrence_time".into(),
        domain::time::TimeSemantic::Realtime => "realtime".into(),
        domain::time::TimeSemantic::Monotonic => "monotonic".into(),
        domain::time::TimeSemantic::Other(other) => other.clone(),
    }
}

fn clock_domain_name(domain_kind: &domain::time::ClockDomain) -> String {
    match domain_kind {
        domain::time::ClockDomain::Host => "host".into(),
        domain::time::ClockDomain::Boot(boot) => format!("boot:{boot}"),
        domain::time::ClockDomain::Unknown => "unknown".into(),
    }
}

fn writer_loop(path: &Path, receiver: std::sync::mpsc::Receiver<WriterCommand>) {
    let connection = match open_writer_connection(path) {
        Ok(connection) => connection,
        Err(_) => {
            // Drain and answer with the stored error once, then exit.
            while let Ok(command) = receiver.recv() {
                match command {
                    WriterCommand::Execute { reply, .. } => {
                        let _ = reply.send(Err(CoreError::Storage(
                            "writer connection could not be opened".into(),
                        )));
                    }
                    WriterCommand::Shutdown { reply } => {
                        let _ = reply.send(Ok(()));
                        return;
                    }
                }
            }
            return;
        }
    };
    while let Ok(command) = receiver.recv() {
        match command {
            WriterCommand::Execute { batch, reply } => {
                let result = run_batch(&connection, &batch);
                let _ = reply.send(result);
            }
            WriterCommand::Shutdown { reply } => {
                let _ = reply.send(Ok(()));
                return;
            }
        }
    }
}

fn open_writer_connection(path: &Path) -> CoreResult<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CoreError::Storage(format!("cannot create {}: {e}", parent.display())))?;
    }
    let connection = Connection::open(path)
        .map_err(|e| CoreError::Storage(format!("cannot open case database: {e}")))?;
    connection
        .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
        .map_err(|e| CoreError::Storage(format!("busy_timeout: {e}")))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| CoreError::Storage(format!("journal_mode: {e}")))?;
    // Integrity-sensitive writes are durable at commit, not at checkpoint.
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|e| CoreError::Storage(format!("synchronous: {e}")))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| CoreError::Storage(format!("foreign_keys: {e}")))?;
    Ok(connection)
}

fn run_batch(connection: &Connection, batch: &WriteBatch) -> CoreResult<BatchResult> {
    let mut applied = 0usize;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|e| CoreError::Storage(format!("cannot begin write transaction: {e}")))?;
    for op in &batch.ops {
        let sql = op.sql();
        let mut statement = transaction
            .prepare(&sql)
            .map_err(|e| CoreError::Storage(format!("prepare {}: {e}", op.table)))?;
        for (index, value) in op.values.iter().enumerate() {
            value
                .bind(&mut statement, index + 1)
                .map_err(|e| CoreError::Storage(format!("bind into {}: {e}", op.table)))?;
        }
        applied += statement
            .raw_execute()
            .map_err(|e| CoreError::Storage(format!("insert into {}: {e}", op.table)))?;
    }
    transaction
        .commit()
        .map_err(|e| CoreError::Storage(format!("commit: {e}")))?;
    Ok(BatchResult {
        attempted: batch.ops.len(),
        applied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_rolls_back_completely_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("case.sqlite");
        crate::storage::migrate::create_schema(&Connection::open(&database).unwrap()).unwrap();
        let writer = CaseWriter::spawn(&database).unwrap();

        let good = WriteBatch::new().push(WriteOp::fact(
            "cases",
            vec!["id", "label", "schema_version", "created_seconds"],
            vec![
                Param::Text("case-1".into()),
                Param::Text("label".into()),
                Param::Int(1),
                Param::Int(0),
            ],
        ));
        assert_eq!(writer.execute(good).unwrap().applied, 1);

        // Second op violates the acquisition foreign key (missing case);
        // nothing of the batch may survive.
        let mixed = WriteBatch::new()
            .push(WriteOp::fact(
                "cases",
                vec!["id", "label", "schema_version", "created_seconds"],
                vec![
                    Param::Text("case-batch".into()),
                    Param::Text("l".into()),
                    Param::Int(1),
                    Param::Int(1_700_000_000),
                ],
            ))
            .push(WriteOp::fact(
                "acquisitions",
                vec!["id", "case_id", "method", "claimed_source", "state"],
                vec![
                    Param::Text("acq-1".into()),
                    Param::Text("missing-case".into()),
                    Param::Text("protected_copy".into()),
                    Param::Text("host".into()),
                    Param::Text("completed".into()),
                ],
            ));
        assert!(
            writer.execute(mixed).is_err(),
            "an FK violation must fail the batch"
        );

        let connection = Connection::open(&database).unwrap();
        let acq_count: i64 = connection
            .query_row("SELECT count(*) FROM acquisitions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(acq_count, 0, "the first op must not survive a failed batch");
        let batch_case: i64 = connection
            .query_row(
                "SELECT count(*) FROM cases WHERE id = 'case-batch'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(batch_case, 0, "nor may any earlier op of the same batch");
        let committed: i64 = connection
            .query_row(
                "SELECT count(*) FROM cases WHERE id = 'case-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(committed, 1, "previously committed batches are unaffected");
    }

    #[test]
    fn idempotent_replay_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("case.sqlite");
        {
            let connection = Connection::open(&database).unwrap();
            crate::storage::migrate::create_schema(&connection).unwrap();
        }
        let writer = CaseWriter::spawn(&database).unwrap();
        let op = WriteOp::fact(
            "cases",
            vec!["id", "label", "schema_version", "created_seconds"],
            vec![
                Param::Text("case-1".into()),
                Param::Text("label".into()),
                Param::Int(1),
                Param::Int(0),
            ],
        );
        assert_eq!(
            writer
                .execute(WriteBatch::new().push(op.clone()))
                .unwrap()
                .applied,
            1
        );
        assert_eq!(
            writer.execute(WriteBatch::new().push(op)).unwrap().applied,
            0
        );
    }

    #[test]
    fn second_writer_in_same_process_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("case.sqlite");
        {
            let connection = Connection::open(&database).unwrap();
            crate::storage::migrate::create_schema(&connection).unwrap();
        }
        let writer = CaseWriter::spawn(&database).unwrap();
        let second = CaseWriter::spawn(&database);
        assert!(second.is_err(), "a second writer must be rejected");
        drop(writer);
        let third = CaseWriter::spawn(&database);
        assert!(third.is_ok(), "released ownership allows a new writer");
    }

    #[test]
    fn checkpoints_are_updatable() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("case.sqlite");
        {
            let connection = Connection::open(&database).unwrap();
            crate::storage::migrate::create_schema(&connection).unwrap();
        }
        let writer = CaseWriter::spawn(&database).unwrap();
        let mut checkpoint = crate::jobs::JobCheckpoint::queued(
            "job-1",
            crate::jobs::JobKind::Acquisition,
            "root:x",
            "digest-x",
        );
        writer.queue_job_checkpoint(&checkpoint).unwrap();
        checkpoint.state = crate::jobs::JobState::Running;
        checkpoint.committed_locator = Some("record 7".into());
        writer.queue_job_checkpoint(&checkpoint).unwrap();

        let connection = Connection::open(&database).unwrap();
        let (state, locator): (String, Option<String>) = connection
            .query_row(
                "SELECT state, committed_locator FROM job_checkpoints WHERE job_id = 'job-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "running");
        assert_eq!(locator.as_deref(), Some("record 7"));
    }

    #[test]
    fn reader_can_view_while_writer_holds_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("case.sqlite");
        {
            let connection = Connection::open(&database).unwrap();
            crate::storage::migrate::create_schema(&connection).unwrap();
        }
        let writer = CaseWriter::spawn(&database).unwrap();
        writer
            .execute(WriteBatch::new().push(WriteOp::fact(
                "cases",
                vec!["id", "label", "schema_version", "created_seconds"],
                vec![
                    Param::Text("case-1".into()),
                    Param::Text("l".into()),
                    Param::Int(1),
                    Param::Int(1_700_000_000),
                ],
            )))
            .unwrap();
        let reader = crate::storage::read::CaseReader::open(&database).unwrap();
        let count: i64 = reader
            .connection()
            .query_row("SELECT count(*) FROM cases", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count, 1,
            "read-only viewing works while the writer owns writes"
        );
    }
}
