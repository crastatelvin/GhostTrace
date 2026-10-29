//! Browser history package ingestion (plan Section 7, P4.3).
//!
//! A package is the captured main SQLite database plus its captured `-wal`
//! and `-shm` sidecars. Parsing never opens the evidence object directly: each
//! member's bytes are verified, copied into a private staging directory, and
//! only the copy is opened. Originals stay untouched.
//!
//! Safety rules:
//! - the schema is validated before any adapter query; views and virtual
//!   tables are rejected instead of being inspected;
//! - `trusted_schema=OFF`, `cell_size_check=ON`, `query_only=ON`, SQLite size
//!   and SQL limits, and a progress deadline are set on the private copy;
//! - every query is a fixed SQL string over fixed table/column names (the only
//!   variable is an integer row limit), and imported configs can never supply
//!   SQL;
//! - an unsupported schema is rejected with the missing *contract* names, not
//!   with a guess at the browser version.
//!
//! Times: Chromium stores microseconds since 1601-01-01; Firefox PRTime stores
//! microseconds since 1970-01-01. Both normalize exactly and keep the raw
//! integer, epoch, and unit next to the instant.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Row};
use serde_json::{Map, Value, json};

use crate::domain::event::NamedEventTimeRef;
use crate::domain::time::{
    ClockDomain, Epoch, EventTime, RawTimeValue, TimeAssumption, TimePrecision, TimeSemantic,
    TimeStatus, TimeUnit, UnixTime,
};
use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::{digest_file, sha256_hex};
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, ParseRunRecord};

use super::{
    ADAPTER_VERSION, Committer, Counts, Diagnostics, EventDraft, EvidenceRef, ImportDiagnostic,
    ImportOutcome, ImportRequest, LogFormat, ParsedRecord, RunSummary, finalize_run,
    find_captured_encoded, hex_bytes, recorded_assumptions, sha256_bytes, truncate_text,
};

const KIND_VISIT: &str = "browser.visit";
const KIND_DOWNLOAD: &str = "browser.download";
const MAX_TEXT_BYTES: usize = 1 << 20;
const QUERY_DEADLINE: Duration = Duration::from_secs(30);

const CHROMIUM_URLS_REQUIRED: &[&str] = &["id", "url", "title", "visit_count", "last_visit_time"];
const CHROMIUM_VISITS_REQUIRED: &[&str] = &["id", "url", "visit_time", "from_visit", "transition"];
const DOWNLOAD_REQUIRED: &[&str] = &["id", "current_path", "target_path", "start_time"];
const DOWNLOAD_OPTIONAL: &[&str] = &[
    "guid",
    "end_time",
    "received_bytes",
    "total_bytes",
    "state",
    "danger_type",
    "interrupt_reason",
    "hash",
    "opened",
    "last_access_time",
    "transient",
    "referrer",
    "site_url",
    "tab_url",
    "tab_referrer_url",
    "http_method",
    "by_ext_id",
    "by_ext_name",
    "etag",
    "last_modified",
    "mime_type",
    "original_mime_type",
];
const URL_CHAIN_REQUIRED: &[&str] = &["id", "chain_index", "url"];
const FIREFOX_PLACES_REQUIRED: &[&str] = &["id", "url", "title", "last_visit_date"];
const FIREFOX_VISITS_REQUIRED: &[&str] =
    &["id", "place_id", "visit_date", "visit_type", "from_visit"];

pub(crate) fn run(
    reader: &CaseReader,
    writer: &CaseWriter,
    case_root: &Path,
    request: &ImportRequest<'_>,
    evidence: &EvidenceRef,
    detected: Option<LogFormat>,
) -> CoreResult<ImportOutcome> {
    let acquisition = evidence.acquisition_id.as_str();
    let wal = find_captured_encoded(
        reader,
        acquisition,
        &format!("{}-wal", evidence.native_path),
    )?;
    let shm = find_captured_encoded(
        reader,
        acquisition,
        &format!("{}-shm", evidence.native_path),
    )?;
    if find_captured_encoded(
        reader,
        acquisition,
        &format!("{}-journal", evidence.native_path),
    )?
    .is_some()
    {
        return Err(CoreError::Unsupported(
            "a rollback-journal sidecar was captured; this adapter only reads a main database \
             with its committed WAL. Capture a checkpointed package instead."
                .to_string(),
        ));
    }
    if shm.is_some() && wal.is_none() {
        return Err(CoreError::Unsupported(
            "a -shm sidecar was captured without its -wal; the package is inconsistent and \
             cannot be treated as complete"
                .to_string(),
        ));
    }

    let package = stage_package(case_root, evidence, wal.as_ref(), shm.as_ref())?;
    let header = read_database_header(&package.main)?;
    if let Some(wal) = wal.as_ref() {
        validate_wal(&case_root.join(&wal.store_subpath))?;
    }

    let deadline = Instant::now() + QUERY_DEADLINE;
    let connection = Connection::open_with_flags(
        &package.main,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| database_error("open private copy", error))?;
    harden(&connection, deadline)?;
    let schema = inspect_schema(&connection)?;
    if !schema.views.is_empty() || !schema.virtual_tables.is_empty() {
        return Err(CoreError::Unsupported(format!(
            "browser package contains {} view(s) and {} virtual table(s); the adapter only \
             queries ordinary tables",
            schema.views.len(),
            schema.virtual_tables.len()
        )));
    }
    let kind = detect_kind(&schema)?;
    quick_check(&connection)?;
    // WAL recovery has happened by now; the remaining statements are reads.
    connection
        .pragma_update(None, "query_only", true)
        .map_err(|error| database_error("set query_only", error))?;

    let fingerprint = schema_fingerprint(kind, &schema);
    let config = json!({
        "format": "browser",
        "adapter_version": ADAPTER_VERSION,
        "kind": kind.id(),
        "schema_fingerprint": fingerprint,
        "main_sha256": sha256_hex(&evidence.sha256),
        "wal_sha256": wal.as_ref().map(|member| sha256_hex(&member.sha256)),
        "shm_sha256": shm.as_ref().map(|member| sha256_hex(&member.sha256)),
        "max_records": request.max_records,
    });
    let config_text = serde_json::to_string(&config)
        .map_err(|error| CoreError::Storage(format!("browser config digest: {error}")))?;
    let config_digest = sha256_hex(&sha256_bytes(config_text.as_bytes()));
    let identity = format!(
        "{}|{}|{}|{}",
        evidence.id,
        kind.parser_id(),
        ADAPTER_VERSION,
        config_digest
    );
    let run_id = format!(
        "pr-{}",
        &sha256_hex(&sha256_bytes(identity.as_bytes()))[..16]
    );

    let mut counts = Counts::default();
    let mut diagnostics = Diagnostics::default();
    if header.wal_mode && wal.is_none() {
        diagnostics.push(
            "wal_missing",
            "",
            "main database is in WAL mode but no -wal sidecar was captured; committed \
             transactions may be absent and this package is not complete on its own",
        );
    }
    if let Some(unavailable) = unavailable_download_fields(&schema) {
        diagnostics.push(
            "download_fields_unavailable",
            "",
            &format!(
                "downloads table lacks these known columns: {}",
                unavailable.join(",")
            ),
        );
    }
    if kind == BrowserKind::Firefox && !schema.has("moz_historyvisits", "source") {
        diagnostics.push(
            "source_fields_unavailable",
            "",
            "moz_historyvisits lacks source; synchronized history cannot be labelled per row",
        );
    }

    let mut run = ParseRunRecord {
        id: run_id.clone(),
        acquisition_id: evidence.acquisition_id.clone(),
        parser_id: kind.parser_id().to_string(),
        parser_version: ADAPTER_VERSION.to_string(),
        config_digest,
        state: "running".to_string(),
        counts_json: counts.to_json(),
        diagnostics_json: "[]".to_string(),
        assumptions_json: recorded_assumptions(LogFormat::Browser, request)?,
    };
    writer.queue_parse_run(&run)?;

    let mut cancelled = false;
    {
        let mut committer = Committer {
            writer,
            run: &mut run,
            evidence,
            run_id: &run_id,
            counts: &mut counts,
            diagnostics: &mut diagnostics,
            pending_observations: Vec::new(),
            pending_events: Vec::new(),
        };
        match kind {
            BrowserKind::Chromium => {
                read_chromium(
                    &connection,
                    &schema,
                    request,
                    &mut committer,
                    &mut cancelled,
                )?;
            }
            BrowserKind::Firefox => {
                read_firefox(
                    &connection,
                    &schema,
                    request,
                    &mut committer,
                    &mut cancelled,
                )?;
            }
        }
        committer.flush()?;
    }

    finalize_run(
        writer,
        RunSummary {
            run,
            counts,
            diagnostics,
            cancelled,
            failed: None,
            evidence,
            parser_id: kind.parser_id(),
            detected,
            declared: request.format,
        },
    )
}

/// Delete the private working copy when the parse ends, success or failure.
struct PrivatePackage {
    dir: PathBuf,
    main: PathBuf,
}

impl Drop for PrivatePackage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stage_package(
    case_root: &Path,
    main: &EvidenceRef,
    wal: Option<&EvidenceRef>,
    shm: Option<&EvidenceRef>,
) -> CoreResult<PrivatePackage> {
    let dir = case_root
        .join("staging")
        .join(format!("browser-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)
        .map_err(|error| CoreError::Storage(format!("create browser staging: {error}")))?;
    let package = PrivatePackage {
        main: dir.join("history.db"),
        dir,
    };
    copy_member(case_root, main, &package.main)?;
    if let Some(wal) = wal {
        copy_member(case_root, wal, &dir_path(&package, "-wal"))?;
    }
    if let Some(shm) = shm {
        copy_member(case_root, shm, &dir_path(&package, "-shm"))?;
    }
    Ok(package)
}

fn dir_path(package: &PrivatePackage, suffix: &str) -> PathBuf {
    let mut path = package.main.clone().into_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn copy_member(case_root: &Path, member: &EvidenceRef, target: &Path) -> CoreResult<()> {
    std::fs::copy(case_root.join(&member.store_subpath), target)
        .map_err(|error| CoreError::Storage(format!("copy package member: {error}")))?;
    let actual = digest_file(target)?;
    if actual.sha256 != member.sha256 {
        return Err(CoreError::IntegrityMismatch);
    }
    Ok(())
}

struct DatabaseHeader {
    wal_mode: bool,
}

fn read_database_header(path: &Path) -> CoreResult<DatabaseHeader> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| CoreError::Storage(format!("open private copy: {error}")))?;
    let mut header = [0_u8; 100];
    let read = file
        .read(&mut header)
        .map_err(|error| CoreError::Storage(format!("read private copy: {error}")))?;
    if read < header.len() || &header[..16] != b"SQLite format 3\0" {
        return Err(CoreError::Unsupported(
            "captured browser object is not a complete SQLite database".to_string(),
        ));
    }
    Ok(DatabaseHeader {
        // 2 means WAL in both header version bytes.
        wal_mode: header[18] == 2 && header[19] == 2,
    })
}

/// Reject a captured WAL whose header cannot describe a WAL at all. SQLite
/// still performs its own checksum and recovery on the private copy.
fn validate_wal(path: &Path) -> CoreResult<()> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| CoreError::Storage(format!("open captured WAL: {error}")))?;
    let mut header = [0_u8; 32];
    file.read_exact(&mut header).map_err(|_| {
        CoreError::Unsupported("captured WAL is shorter than its header".to_string())
    })?;
    let magic = u32::from_be_bytes(
        header[0..4]
            .try_into()
            .expect("four bytes from a fixed header"),
    );
    if magic != 0x377f_0682 && magic != 0x377f_0683 {
        return Err(CoreError::Unsupported(
            "captured WAL header magic is invalid; the package is inconsistent".to_string(),
        ));
    }
    let page_size = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .expect("four bytes from a fixed header"),
    );
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(CoreError::Unsupported(
            "captured WAL declares an invalid page size; the package is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn harden(connection: &Connection, deadline: Instant) -> CoreResult<()> {
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, MAX_TEXT_BYTES as i32),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 100_000),
        (Limit::SQLITE_LIMIT_COLUMN, 256),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 100),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 20),
        (Limit::SQLITE_LIMIT_VDBE_OP, 250_000),
    ] {
        connection
            .set_limit(limit, value)
            .map_err(|error| database_error("set SQLite limit", error))?;
    }
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(|error| database_error("set trusted_schema", error))?;
    connection
        .pragma_update(None, "cell_size_check", true)
        .map_err(|error| database_error("set cell_size_check", error))?;
    connection
        .progress_handler(20_000, Some(move || Instant::now() >= deadline))
        .map_err(|error| database_error("set query deadline", error))?;
    Ok(())
}

struct Column {
    name: String,
    declared_type: String,
    not_null: bool,
    primary_key: bool,
}

struct Schema {
    tables: BTreeMap<String, Vec<Column>>,
    views: Vec<String>,
    virtual_tables: Vec<String>,
}

impl Schema {
    fn columns(&self, table: &str) -> BTreeSet<&str> {
        self.tables
            .get(table)
            .map(|columns| columns.iter().map(|column| column.name.as_str()).collect())
            .unwrap_or_default()
    }

    fn has(&self, table: &str, column: &str) -> bool {
        self.tables
            .get(table)
            .is_some_and(|columns| columns.iter().any(|entry| entry.name == column))
    }
}

fn inspect_schema(connection: &Connection) -> CoreResult<Schema> {
    let mut statement = connection
        .prepare("SELECT type, name, COALESCE(sql, '') FROM sqlite_schema ORDER BY type, name")
        .map_err(|error| database_error("inspect schema", error))?;
    let entries = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| database_error("inspect schema", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| database_error("inspect schema", error))?;

    let mut schema = Schema {
        tables: BTreeMap::new(),
        views: Vec::new(),
        virtual_tables: Vec::new(),
    };
    for (kind, name, sql) in entries {
        match kind.as_str() {
            "view" => schema.views.push(name),
            "table" => {
                if sql.to_ascii_uppercase().contains("VIRTUAL TABLE") {
                    schema.virtual_tables.push(name);
                } else {
                    schema
                        .tables
                        .insert(name.clone(), table_columns(connection, &name)?);
                }
            }
            _ => {}
        }
    }
    Ok(schema)
}

fn table_columns(connection: &Connection, table: &str) -> CoreResult<Vec<Column>> {
    let mut statement = connection
        .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1) ORDER BY cid")
        .map_err(|error| database_error("inspect table", error))?;
    statement
        .query_map(rusqlite::params![table], |row| {
            Ok(Column {
                name: row.get(0)?,
                declared_type: row.get(1)?,
                not_null: row.get::<_, i64>(2)? != 0,
                primary_key: row.get::<_, i64>(3)? != 0,
            })
        })
        .map_err(|error| database_error("inspect table", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| database_error("inspect table", error))
}

fn quick_check(connection: &Connection) -> CoreResult<()> {
    let mut statement = connection
        .prepare("PRAGMA quick_check")
        .map_err(|error| database_error("quick_check", error))?;
    let mut rows = statement
        .query([])
        .map_err(|error| database_error("quick_check", error))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| database_error("quick_check", error))?
    {
        let result: String = row
            .get(0)
            .map_err(|error| database_error("quick_check", error))?;
        if result != "ok" {
            // The detail can quote database content, so it stays out of the
            // message; the class of failure is enough.
            return Err(CoreError::CorruptEvidence);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserKind {
    Chromium,
    Firefox,
}

impl BrowserKind {
    fn id(self) -> &'static str {
        match self {
            BrowserKind::Chromium => "chromium",
            BrowserKind::Firefox => "firefox",
        }
    }

    fn parser_id(self) -> &'static str {
        match self {
            BrowserKind::Chromium => "browser.chromium",
            BrowserKind::Firefox => "browser.firefox",
        }
    }

    fn fingerprint_tables(self) -> &'static [&'static str] {
        match self {
            BrowserKind::Chromium => &["urls", "visits", "downloads", "downloads_url_chains"],
            BrowserKind::Firefox => &["moz_places", "moz_historyvisits"],
        }
    }
}

fn detect_kind(schema: &Schema) -> CoreResult<BrowserKind> {
    let chromium = schema.tables.contains_key("urls") && schema.tables.contains_key("visits");
    let firefox =
        schema.tables.contains_key("moz_places") && schema.tables.contains_key("moz_historyvisits");
    match (chromium, firefox) {
        (true, true) => Err(CoreError::Unsupported(
            "browser package matches both Chromium and Firefox contracts; refusing to guess"
                .to_string(),
        )),
        (false, false) => Err(CoreError::Unsupported(
            "no supported Chromium or Firefox history tables were found; the package is \
             preserved but not interpreted"
                .to_string(),
        )),
        (true, false) => {
            require_columns(schema, "urls", CHROMIUM_URLS_REQUIRED)?;
            require_columns(schema, "visits", CHROMIUM_VISITS_REQUIRED)?;
            if schema.tables.contains_key("downloads") {
                require_columns(schema, "downloads", DOWNLOAD_REQUIRED)?;
            }
            if schema.tables.contains_key("downloads_url_chains") {
                require_columns(schema, "downloads_url_chains", URL_CHAIN_REQUIRED)?;
            }
            Ok(BrowserKind::Chromium)
        }
        (false, true) => {
            require_columns(schema, "moz_places", FIREFOX_PLACES_REQUIRED)?;
            require_columns(schema, "moz_historyvisits", FIREFOX_VISITS_REQUIRED)?;
            Ok(BrowserKind::Firefox)
        }
    }
}

fn require_columns(schema: &Schema, table: &str, required: &[&str]) -> CoreResult<()> {
    let columns = schema.columns(table);
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|name| !columns.contains(name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    // Only the fixed contract names are reported, never imported SQL text.
    Err(CoreError::Unsupported(format!(
        "browser package table {table} lacks required columns: {}",
        missing.join(", ")
    )))
}

fn schema_fingerprint(kind: BrowserKind, schema: &Schema) -> String {
    let mut text = String::from(kind.parser_id());
    for table in kind.fingerprint_tables() {
        let Some(columns) = schema.tables.get(*table) else {
            continue;
        };
        text.push('\n');
        text.push_str(table);
        for column in columns {
            text.push('\n');
            text.push_str(&column.name);
            text.push('\u{1f}');
            text.push_str(&column.declared_type);
            text.push('\u{1f}');
            text.push(if column.not_null { '1' } else { '0' });
            text.push('\u{1f}');
            text.push(if column.primary_key { '1' } else { '0' });
        }
    }
    sha256_hex(&sha256_bytes(text.as_bytes()))
}

fn unavailable_download_fields(schema: &Schema) -> Option<Vec<&'static str>> {
    if !schema.tables.contains_key("downloads") {
        return None;
    }
    let columns = schema.columns("downloads");
    let mut unavailable: Vec<&'static str> = DOWNLOAD_OPTIONAL
        .iter()
        .copied()
        .filter(|name| !columns.contains(name))
        .collect();
    if !schema.tables.contains_key("downloads_url_chains") {
        unavailable.push("url_chain");
    }
    if unavailable.is_empty() {
        None
    } else {
        Some(unavailable)
    }
}

fn read_chromium(
    connection: &Connection,
    schema: &Schema,
    request: &ImportRequest<'_>,
    committer: &mut Committer<'_>,
    cancelled: &mut bool,
) -> CoreResult<()> {
    read_chromium_visits(connection, schema, request, committer, cancelled)?;
    if !*cancelled {
        read_chromium_downloads(connection, schema, request, committer, cancelled)?;
    }
    Ok(())
}

fn read_chromium_visits(
    connection: &Connection,
    schema: &Schema,
    request: &ImportRequest<'_>,
    committer: &mut Committer<'_>,
    cancelled: &mut bool,
) -> CoreResult<()> {
    let visits = schema.columns("visits");
    let optional = |name: &str, alias: &str| optional_expr(&visits, alias, name);
    let sql = format!(
        "SELECT v.id, v.visit_time, v.from_visit, v.transition,
                {}, {}, {}, {},
                u.url, u.title, u.visit_count,
                rv.id, ru.url
         FROM visits AS v
         JOIN urls AS u ON u.id = v.url
         LEFT JOIN visits AS rv ON rv.id = v.from_visit
         LEFT JOIN urls AS ru ON ru.id = rv.url
         ORDER BY v.visit_time, v.id
         LIMIT ?1",
        optional("visit_duration", "v"),
        optional("originator_cache_guid", "v"),
        optional("is_known_to_sync", "v"),
        optional("opener_visit", "v"),
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| database_error("prepare visits", error))?;
    let remaining = request.max_records.saturating_sub(committer.counts.records);
    let mut rows = statement
        .query(rusqlite::params![remaining.saturating_add(1) as i64])
        .map_err(|error| database_error("query visits", error))?;
    let mut seen = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| database_error("read visits", error))?
    {
        if request.cancelled.load(Ordering::Relaxed) {
            *cancelled = true;
            return Ok(());
        }
        if seen >= remaining {
            committer.diagnostics.push(
                "record_limit",
                "table:visits",
                &format!(
                    "import stopped at the configured limit of {} rows",
                    request.max_records
                ),
            );
            return Ok(());
        }
        let parsed = chromium_visit(row)?;
        committer.counts.records += 1;
        committer.commit(parsed)?;
        seen += 1;
    }
    Ok(())
}

fn chromium_visit(row: &Row<'_>) -> CoreResult<ParsedRecord> {
    let id = required_integer(row, 0)?;
    let locator = format!("table:visits:rowid:{id}");
    let mut diagnostics = Vec::new();
    let mut fields = Map::new();
    fields.insert("rowid".into(), json!(id));
    for (index, name) in [
        (1, "visit_time"),
        (2, "from_visit"),
        (3, "transition"),
        (4, "visit_duration"),
        (5, "originator_cache_guid"),
        (6, "is_known_to_sync"),
        (7, "opener_visit"),
        (10, "url_visit_count"),
        (11, "referrer_visit_id"),
    ] {
        fields.insert(name.into(), cell(row, index)?);
    }
    let url = text_value(row, 8)?;
    let title = text_value(row, 9)?;
    fields.insert("url".into(), cell(row, 8)?);
    fields.insert("title".into(), cell(row, 9)?);
    fields.insert("referrer_url".into(), cell(row, 12)?);

    let origin = text_value(row, 5)?.filter(|value| !value.is_empty());
    let known_to_sync = integer_value(row, 6)?;
    let sync_status = if origin.is_some() {
        "imported"
    } else if known_to_sync == Some(1) {
        "sync_known"
    } else if known_to_sync == Some(0) {
        "local"
    } else {
        "unknown"
    };
    fields.insert("sync_status".into(), Value::String(sync_status.to_string()));

    let visit_time = integer_value(row, 1)?.unwrap_or(0);
    let time = micro_time(
        visit_time,
        Epoch::Chrome1601,
        "__visit_time",
        true,
        &locator,
        &mut diagnostics,
    );
    let summary = summary_for(title.as_deref(), url.as_deref(), "visit");
    Ok(ParsedRecord {
        mapped_json: None,
        locator,
        locator_kind: "logical_row",
        raw_json: Some(Value::Object(fields).to_string()),
        event: Some(EventDraft {
            kind: KIND_VISIT.to_string(),
            summary,
            host: None,
            times: vec![NamedEventTimeRef {
                name: "visit".to_string(),
                semantic: TimeSemantic::OccurrenceTime,
                value: time,
            }],
        }),
        diagnostics,
    })
}

fn read_chromium_downloads(
    connection: &Connection,
    schema: &Schema,
    request: &ImportRequest<'_>,
    committer: &mut Committer<'_>,
    cancelled: &mut bool,
) -> CoreResult<()> {
    if !schema.tables.contains_key("downloads") {
        return Ok(());
    }
    let columns = schema.columns("downloads");
    let mut select = String::from("d.id, d.current_path, d.target_path, d.start_time");
    for name in DOWNLOAD_OPTIONAL {
        select.push_str(", ");
        select.push_str(&optional_expr(&columns, "d", name));
    }
    let url_chain = if schema.tables.contains_key("downloads_url_chains") {
        load_url_chains(connection, request)?
    } else {
        BTreeMap::new()
    };

    let remaining = request.max_records.saturating_sub(committer.counts.records);
    let sql = format!("SELECT {select} FROM downloads AS d ORDER BY d.start_time, d.id LIMIT ?1");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| database_error("prepare downloads", error))?;
    let mut rows = statement
        .query(rusqlite::params![remaining.saturating_add(1) as i64])
        .map_err(|error| database_error("query downloads", error))?;
    let mut seen = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| database_error("read downloads", error))?
    {
        if request.cancelled.load(Ordering::Relaxed) {
            *cancelled = true;
            return Ok(());
        }
        if seen >= remaining {
            committer.diagnostics.push(
                "record_limit",
                "table:downloads",
                &format!(
                    "import stopped at the configured limit of {} rows",
                    request.max_records
                ),
            );
            return Ok(());
        }
        let parsed = chromium_download(row, &url_chain, &columns)?;
        committer.counts.records += 1;
        committer.commit(parsed)?;
        seen += 1;
    }
    Ok(())
}

/// URL chains are kept in chain order per download id. The row cap is the same
/// as the record cap; exceeding it is reported rather than silently cut.
fn load_url_chains(
    connection: &Connection,
    request: &ImportRequest<'_>,
) -> CoreResult<BTreeMap<i64, Vec<Value>>> {
    let mut statement = connection
        .prepare(
            "SELECT id, url FROM downloads_url_chains
             ORDER BY id, chain_index
             LIMIT ?1",
        )
        .map_err(|error| database_error("prepare URL chains", error))?;
    let mut rows = statement
        .query(rusqlite::params![
            request.max_records.saturating_add(1) as i64
        ])
        .map_err(|error| database_error("query URL chains", error))?;
    let mut chains: BTreeMap<i64, Vec<Value>> = BTreeMap::new();
    let mut total = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| database_error("read URL chains", error))?
    {
        total += 1;
        if total > request.max_records {
            return Err(CoreError::ResourceLimit);
        }
        let id: i64 = row
            .get(0)
            .map_err(|error| database_error("read URL chains", error))?;
        chains.entry(id).or_default().push(cell(row, 1)?);
    }
    Ok(chains)
}

fn chromium_download(
    row: &Row<'_>,
    url_chain: &BTreeMap<i64, Vec<Value>>,
    columns: &BTreeSet<&str>,
) -> CoreResult<ParsedRecord> {
    let id = required_integer(row, 0)?;
    let locator = format!("table:downloads:rowid:{id}");
    let mut diagnostics = Vec::new();
    let mut fields = Map::new();
    fields.insert("rowid".into(), json!(id));
    fields.insert("current_path".into(), cell(row, 1)?);
    fields.insert("target_path".into(), cell(row, 2)?);
    fields.insert("start_time".into(), cell(row, 3)?);
    for (offset, name) in DOWNLOAD_OPTIONAL.iter().enumerate() {
        if columns.contains(name) {
            fields.insert((*name).into(), cell(row, 4 + offset)?);
        }
    }
    if let Some(chain) = url_chain.get(&id) {
        fields.insert("url_chain".into(), Value::Array(chain.clone()));
    }

    let start = integer_value(row, 3)?.unwrap_or(0);
    let start_time = micro_time(
        start,
        Epoch::Chrome1601,
        "__download_start_time",
        true,
        &locator,
        &mut diagnostics,
    );
    let end = integer_value(row, 5)?;
    let end_time = end.map(|value| {
        micro_time(
            value,
            Epoch::Chrome1601,
            "__download_end_time",
            true,
            &locator,
            &mut diagnostics,
        )
    });
    let mut times = vec![NamedEventTimeRef {
        name: "start".to_string(),
        semantic: TimeSemantic::OccurrenceTime,
        value: start_time,
    }];
    if let Some(end_time) = end_time {
        times.push(NamedEventTimeRef {
            name: "end".to_string(),
            semantic: TimeSemantic::OccurrenceTime,
            value: end_time,
        });
        // If the producer never set a start time, the end time is the only
        // observed instant; it becomes the chosen time instead of hiding it.
        if times[0].value.status != TimeStatus::Resolved
            && times[1].value.status == TimeStatus::Resolved
        {
            times.swap(0, 1);
        }
    }
    let target = text_value(row, 2)?;
    let current = text_value(row, 1)?;
    let summary = summary_for(target.as_deref(), current.as_deref(), "download");
    Ok(ParsedRecord {
        mapped_json: None,
        locator,
        locator_kind: "logical_row",
        raw_json: Some(Value::Object(fields).to_string()),
        event: Some(EventDraft {
            kind: KIND_DOWNLOAD.to_string(),
            summary,
            host: None,
            times,
        }),
        diagnostics,
    })
}

fn read_firefox(
    connection: &Connection,
    schema: &Schema,
    request: &ImportRequest<'_>,
    committer: &mut Committer<'_>,
    cancelled: &mut bool,
) -> CoreResult<()> {
    let visits = schema.columns("moz_historyvisits");
    let optional = |name: &str, alias: &str| optional_expr(&visits, alias, name);
    let sql = format!(
        "SELECT v.id, v.visit_date, v.visit_type, v.from_visit,
                {}, {}, p.url, p.title, p.visit_count,
                rv.id, rp.url
         FROM moz_historyvisits AS v
         JOIN moz_places AS p ON p.id = v.place_id
         LEFT JOIN moz_historyvisits AS rv ON rv.id = v.from_visit
         LEFT JOIN moz_places AS rp ON rp.id = rv.place_id
         ORDER BY v.visit_date, v.id
         LIMIT ?1",
        optional("source", "v"),
        optional("session", "v"),
    );
    let remaining = request.max_records.saturating_sub(committer.counts.records);
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| database_error("prepare Firefox visits", error))?;
    let mut rows = statement
        .query(rusqlite::params![remaining.saturating_add(1) as i64])
        .map_err(|error| database_error("query Firefox visits", error))?;
    let mut seen = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| database_error("read Firefox visits", error))?
    {
        if request.cancelled.load(Ordering::Relaxed) {
            *cancelled = true;
            return Ok(());
        }
        if seen >= remaining {
            committer.diagnostics.push(
                "record_limit",
                "table:moz_historyvisits",
                &format!(
                    "import stopped at the configured limit of {} rows",
                    request.max_records
                ),
            );
            return Ok(());
        }
        let parsed = firefox_visit(row)?;
        committer.counts.records += 1;
        committer.commit(parsed)?;
        seen += 1;
    }
    Ok(())
}

fn firefox_visit(row: &Row<'_>) -> CoreResult<ParsedRecord> {
    let id = required_integer(row, 0)?;
    let locator = format!("table:moz_historyvisits:rowid:{id}");
    let mut diagnostics = Vec::new();
    let mut fields = Map::new();
    fields.insert("rowid".into(), json!(id));
    for (index, name) in [
        (1, "visit_date"),
        (2, "visit_type"),
        (3, "from_visit"),
        (4, "source"),
        (5, "session"),
        (8, "url_visit_count"),
        (9, "referrer_visit_id"),
    ] {
        fields.insert(name.into(), cell(row, index)?);
    }
    let url = text_value(row, 6)?;
    let title = text_value(row, 7)?;
    fields.insert("url".into(), cell(row, 6)?);
    fields.insert("title".into(), cell(row, 7)?);
    fields.insert("referrer_url".into(), cell(row, 10)?);

    let source = integer_value(row, 4)?;
    let history_source = match source {
        Some(0) => "local",
        Some(1) => "synced",
        Some(_) => "unknown",
        None => "unknown",
    };
    fields.insert(
        "history_source".into(),
        Value::String(history_source.to_string()),
    );

    let visit_date = integer_value(row, 1)?.unwrap_or(0);
    let time = micro_time(
        visit_date,
        Epoch::Unix,
        "__visit_date",
        true,
        &locator,
        &mut diagnostics,
    );
    Ok(ParsedRecord {
        mapped_json: None,
        locator,
        locator_kind: "logical_row",
        raw_json: Some(Value::Object(fields).to_string()),
        event: Some(EventDraft {
            kind: KIND_VISIT.to_string(),
            summary: summary_for(title.as_deref(), url.as_deref(), "visit"),
            host: None,
            times: vec![NamedEventTimeRef {
                name: "visit".to_string(),
                semantic: TimeSemantic::OccurrenceTime,
                value: time,
            }],
        }),
        diagnostics,
    })
}

fn optional_expr(columns: &BTreeSet<&str>, alias: &str, name: &str) -> String {
    if columns.contains(name) {
        format!("{alias}.{name}")
    } else {
        "NULL".to_string()
    }
}

fn cell(row: &Row<'_>, index: usize) -> CoreResult<Value> {
    match row
        .get_ref(index)
        .map_err(|error| database_error("read browser field", error))?
    {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Integer(value) => Ok(Value::from(value)),
        ValueRef::Real(value) => Ok(Value::from(value)),
        ValueRef::Text(bytes) => Ok(match std::str::from_utf8(bytes) {
            Ok(text) => Value::String(text.to_string()),
            Err(_) => json!({ "binary_hex": hex_bytes(bytes) }),
        }),
        ValueRef::Blob(bytes) => Ok(json!({ "binary_hex": hex_bytes(bytes) })),
    }
}

fn required_integer(row: &Row<'_>, index: usize) -> CoreResult<i64> {
    integer_value(row, index)?.ok_or(CoreError::CorruptEvidence)
}

fn integer_value(row: &Row<'_>, index: usize) -> CoreResult<Option<i64>> {
    match row
        .get_ref(index)
        .map_err(|error| database_error("read browser field", error))?
    {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) => Ok(Some(value)),
        _ => Ok(None),
    }
}

fn text_value(row: &Row<'_>, index: usize) -> CoreResult<Option<String>> {
    match row
        .get_ref(index)
        .map_err(|error| database_error("read browser field", error))?
    {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => Ok(std::str::from_utf8(bytes).ok().map(str::to_string)),
        _ => Ok(None),
    }
}

fn summary_for(title: Option<&str>, url_or_path: Option<&str>, fallback: &str) -> String {
    let chosen = title
        .filter(|value| !value.is_empty())
        .or_else(|| url_or_path.filter(|value| !value.is_empty()))
        .unwrap_or(fallback);
    truncate_text(chosen, 512)
}

fn micro_time(
    value: i64,
    epoch: Epoch,
    field: &'static str,
    zero_means_unset: bool,
    locator: &str,
    diagnostics: &mut Vec<ImportDiagnostic>,
) -> EventTime {
    let raw_value = i128::from(value);
    if zero_means_unset && value == 0 {
        diagnostics.push(ImportDiagnostic {
            code: "time_missing".to_string(),
            locator: locator.to_string(),
            detail: format!("{field} is the producer's unset sentinel; no instant was inferred"),
        });
        return EventTime {
            status: TimeStatus::Unresolved,
            candidates: Vec::new(),
            raw: Some(RawTimeValue::integer_raw(
                field,
                raw_value,
                epoch,
                TimeUnit::Micros,
            )),
            semantic: TimeSemantic::OccurrenceTime,
            clock_domain: ClockDomain::Host,
            declared_precision: TimePrecision::Micros,
            assumptions: vec![TimeAssumption {
                description: "the stored value is the producer's unset sentinel".to_string(),
                zone: None,
                year_assumed: None,
            }],
        };
    }
    match UnixTime::from_parts(raw_value, epoch, TimeUnit::Micros) {
        Ok(instant) => EventTime {
            status: TimeStatus::Resolved,
            candidates: vec![instant],
            raw: Some(RawTimeValue::integer_raw(
                field,
                raw_value,
                epoch,
                TimeUnit::Micros,
            )),
            semantic: TimeSemantic::OccurrenceTime,
            clock_domain: ClockDomain::Host,
            declared_precision: TimePrecision::Micros,
            assumptions: vec![TimeAssumption {
                description: match epoch {
                    Epoch::Chrome1601 => {
                        "microseconds since 1601-01-01 UTC (Chromium time)".to_string()
                    }
                    _ => "microseconds since the Unix epoch (Firefox PRTime)".to_string(),
                },
                zone: None,
                year_assumed: None,
            }],
        },
        Err(_) => {
            diagnostics.push(ImportDiagnostic {
                code: "invalid_time".to_string(),
                locator: locator.to_string(),
                detail: format!("{field} is outside the representable range"),
            });
            EventTime {
                status: TimeStatus::Invalid,
                candidates: Vec::new(),
                raw: Some(RawTimeValue::integer_raw(
                    field,
                    raw_value,
                    epoch,
                    TimeUnit::Micros,
                )),
                semantic: TimeSemantic::OccurrenceTime,
                clock_domain: ClockDomain::Host,
                declared_precision: TimePrecision::Micros,
                assumptions: vec![TimeAssumption {
                    description: format!("{field} cannot be interpreted as an instant"),
                    zone: None,
                    year_assumed: None,
                }],
            }
        }
    }
}

fn database_error(context: &str, error: rusqlite::Error) -> CoreError {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            CoreError::CorruptEvidence
        }
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            CoreError::ResourceLimit
        }
        other => CoreError::Storage(format!("{context}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROMIUM_VISITS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/browser/chromium-visits.sql"
    ));
    const CHROMIUM_DOWNLOADS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/browser/chromium-downloads.sql"
    ));
    const FIREFOX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/browser/firefox.sql"
    ));

    fn schema(sql: &str) -> Schema {
        let connection = Connection::open_in_memory().expect("memory");
        connection.execute_batch(sql).expect("schema");
        inspect_schema(&connection).expect("inspect")
    }

    #[test]
    fn chromium_visit_fixture_fingerprint_is_stable() {
        let schema = schema(CHROMIUM_VISITS);
        let kind = detect_kind(&schema).expect("kind");
        assert_eq!(kind, BrowserKind::Chromium);
        assert_eq!(
            schema_fingerprint(kind, &schema),
            "f2d4b0781f8d12de18205bc636eb6b76f3152b7ba36d8d258d47156754deae16"
        );
    }

    #[test]
    fn chromium_download_fixture_fingerprint_is_stable() {
        let schema = schema(CHROMIUM_DOWNLOADS);
        let kind = detect_kind(&schema).expect("kind");
        assert_eq!(kind, BrowserKind::Chromium);
        assert_eq!(
            schema_fingerprint(kind, &schema),
            "ff301a6f72e24e351de3192155ecd344a9673d003d24c64fcefd7ba2370b493c"
        );
    }

    #[test]
    fn firefox_fixture_fingerprint_is_stable() {
        let schema = schema(FIREFOX);
        let kind = detect_kind(&schema).expect("kind");
        assert_eq!(kind, BrowserKind::Firefox);
        assert_eq!(
            schema_fingerprint(kind, &schema),
            "a40374e3ec8fe005161985a5738750be3a9c415048637e482b101886f2ed1e11"
        );
    }

    #[test]
    fn a_long_sql_statement_is_rejected_by_the_limit() {
        let connection = Connection::open_in_memory().expect("memory");
        harden(&connection, Instant::now() + QUERY_DEADLINE).expect("harden");
        let sql = format!("SELECT {}", "1+".repeat(200_000));
        assert!(connection.prepare(&sql).is_err());
    }

    #[test]
    fn the_progress_deadline_interrupts_a_runaway_query() {
        let connection = Connection::open_in_memory().expect("memory");
        harden(&connection, Instant::now()).expect("harden");
        let result = connection.query_row(
            "WITH RECURSIVE count(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM count)
             SELECT sum(x) FROM count",
            [],
            |row| row.get::<_, i64>(0),
        );
        assert!(result.is_err());
    }
}
