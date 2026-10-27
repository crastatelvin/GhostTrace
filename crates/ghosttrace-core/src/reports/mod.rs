//! Versioned, self-contained report export (plan Sections 9, 12; P3.2).
//!
//! Reports are built from the recorded case, never from a fresh source read,
//! and published atomically: a failure leaves no directory that looks like a
//! completed export, and an existing report is never overwritten.

pub mod html;
pub mod json;

use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::storage::read::CaseReader;

/// Report format identity. Changing the shape requires a new version.
pub const REPORT_FORMAT: &str = "ghosttrace-report/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportV1 {
    pub format: String,
    pub report_id: String,
    pub created_utc: String,
    pub tool_version: String,
    pub case: CaseView,
    pub acquisition: AcquisitionView,
    pub coverage: CoverageView,
    pub objects: Vec<ObjectView>,
    pub timeline: Vec<TimelineView>,
    pub provenance: ProvenanceView,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseView {
    pub case_id: String,
    pub label: String,
    pub display_timezone: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionView {
    pub id: String,
    pub method: String,
    pub claimed_source: String,
    pub state: String,
    pub link_policy: String,
    pub roots: Vec<String>,
    pub started_seconds: Option<i64>,
    pub ended_seconds: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageView {
    pub captured: u64,
    pub excluded: u64,
    pub inaccessible: u64,
    pub unstable: u64,
    pub vanished: u64,
    pub unsupported: u64,
    pub unobserved: u64,
    pub gaps: Vec<GapView>,
    /// False when the gap list was truncated for the report.
    pub gaps_complete: bool,
}

impl CoverageView {
    pub fn total_gaps(&self) -> u64 {
        self.excluded
            + self.inaccessible
            + self.unstable
            + self.vanished
            + self.unsupported
            + self.unobserved
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapView {
    /// Root-qualified encoded path; ASCII by construction.
    pub path: String,
    pub status: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectView {
    pub path: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineView {
    pub event_id: String,
    pub source: String,
    pub kind: String,
    pub summary: String,
    pub host_claim: Option<String>,
    pub chosen_seconds: Option<i64>,
    pub chosen_nanos: i64,
    pub time_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceView {
    pub generated_by: String,
    pub tool_version: String,
    pub method: String,
    pub claimed_source: String,
    pub link_policy: String,
    pub roots: Vec<String>,
    /// Filters/limits applied to the timeline selection.
    pub timeline_selection: String,
    /// Alpha reports carry no signature; say so where a reader will look.
    pub signed: bool,
}

/// Case-level facts the reader cannot derive from a single acquisition.
#[derive(Debug, Clone)]
pub struct ReportContext {
    pub case_id: String,
    pub label: String,
    pub display_timezone: String,
    pub tool_version: String,
}

#[derive(Debug, Clone)]
pub struct ReportSelection {
    /// Latest acquisition when `None`.
    pub acquisition_id: Option<String>,
    pub event_limit: u32,
}

impl Default for ReportSelection {
    fn default() -> Self {
        Self {
            acquisition_id: None,
            event_limit: 500,
        }
    }
}

/// Gap rows embedded in a report; the full ledger stays in the case.
pub const MAX_REPORT_GAPS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedReport {
    pub directory: PathBuf,
    pub json_path: PathBuf,
    pub html_path: PathBuf,
}

/// Build a report for one acquisition from recorded rows only.
pub fn build_report(
    reader: &CaseReader,
    context: &ReportContext,
    selection: &ReportSelection,
) -> CoreResult<ReportV1> {
    let connection = reader.connection();
    let acquisition = connection
        .query_row(
            "SELECT id, method, claimed_source, state, roots_json, link_policy,
                    started_seconds, ended_seconds
             FROM acquisitions
             WHERE (?1 IS NULL OR id = ?1)
             ORDER BY started_seconds DESC, id DESC
             LIMIT 1",
            [selection.acquisition_id.as_deref()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .map_err(|error| match selection.acquisition_id.as_deref() {
            Some(id) => CoreError::InvalidInput(format!("acquisition {id}: {error}")),
            None => CoreError::InvalidInput(format!("no acquisition in this case: {error}")),
        })?;
    let roots: Vec<ManifestRootLike> = serde_json::from_str(&acquisition.4)
        .map_err(|error| CoreError::Storage(format!("roots json: {error}")))?;
    let roots: Vec<String> = roots
        .into_iter()
        .map(|root| root.native_path_encoded)
        .collect();

    let mut coverage = CoverageView {
        gaps_complete: true,
        ..CoverageView::default()
    };
    {
        let mut statement = connection
            .prepare(
                "SELECT status, count(*) FROM coverage
                 WHERE acquisition_id = ?1 GROUP BY status",
            )
            .map_err(|error| CoreError::Storage(format!("report coverage: {error}")))?;
        let rows = statement
            .query_map([&acquisition.0], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|error| CoreError::Storage(format!("report coverage: {error}")))?;
        for row in rows {
            let (status, count) =
                row.map_err(|error| CoreError::Storage(format!("report coverage: {error}")))?;
            let count = count.max(0) as u64;
            match status.as_str() {
                "captured" => coverage.captured = count,
                "excluded" => coverage.excluded = count,
                "inaccessible" => coverage.inaccessible = count,
                "unstable" => coverage.unstable = count,
                "vanished" => coverage.vanished = count,
                "unsupported" => coverage.unsupported = count,
                "unobserved" => coverage.unobserved = count,
                _ => {}
            }
        }
    }
    {
        let mut statement = connection
            .prepare(
                "SELECT path_key, status, coalesce(error_code, '')
                 FROM coverage
                 WHERE acquisition_id = ?1 AND status <> 'captured'
                 ORDER BY path_key
                 LIMIT ?2",
            )
            .map_err(|error| CoreError::Storage(format!("report gaps: {error}")))?;
        let rows = statement
            .query_map(
                rusqlite::params![&acquisition.0, (MAX_REPORT_GAPS + 1) as i64],
                |row| {
                    Ok(GapView {
                        path: row.get(0)?,
                        status: row.get(1)?,
                        code: row.get(2)?,
                    })
                },
            )
            .map_err(|error| CoreError::Storage(format!("report gaps: {error}")))?;
        for row in rows {
            coverage
                .gaps
                .push(row.map_err(|error| CoreError::Storage(format!("report gaps: {error}")))?);
        }
        if coverage.gaps.len() > MAX_REPORT_GAPS {
            coverage.gaps.truncate(MAX_REPORT_GAPS);
            coverage.gaps_complete = false;
        }
    }

    let mut objects = Vec::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT native_path_encoded, sha256, byte_length
                 FROM evidence_objects
                 WHERE acquisition_id = ?1 AND digest_status = 'complete'
                 ORDER BY native_path_encoded",
            )
            .map_err(|error| CoreError::Storage(format!("report objects: {error}")))?;
        let rows = statement
            .query_map([&acquisition.0], |row| {
                Ok(ObjectView {
                    path: row.get(0)?,
                    sha256: hex(row.get::<_, Vec<u8>>(1)?),
                    byte_length: row.get::<_, i64>(2)?.max(0) as u64,
                })
            })
            .map_err(|error| CoreError::Storage(format!("report objects: {error}")))?;
        for row in rows {
            objects
                .push(row.map_err(|error| CoreError::Storage(format!("report objects: {error}")))?);
        }
    }

    let event_limit = selection.event_limit.clamp(1, 5_000);
    let mut timeline = Vec::new();
    {
        let mut statement = connection
            .prepare(
                "SELECT e.id, p.parser_id, e.kind, e.summary, e.host_claim,
                        e.chosen_seconds, e.chosen_nanos, e.time_status
                 FROM events e
                 JOIN parse_runs p ON p.id = e.parse_run_id
                 WHERE p.acquisition_id = ?1
                 ORDER BY (e.chosen_seconds IS NULL), e.chosen_seconds, e.chosen_nanos, e.id
                 LIMIT ?2",
            )
            .map_err(|error| CoreError::Storage(format!("report timeline: {error}")))?;
        let rows = statement
            .query_map(
                rusqlite::params![&acquisition.0, event_limit as i64],
                |row| {
                    Ok(TimelineView {
                        event_id: row.get(0)?,
                        source: row.get(1)?,
                        kind: row.get(2)?,
                        summary: row.get(3)?,
                        host_claim: row.get(4)?,
                        chosen_seconds: row.get(5)?,
                        chosen_nanos: row.get(6)?,
                        time_status: row.get(7)?,
                    })
                },
            )
            .map_err(|error| CoreError::Storage(format!("report timeline: {error}")))?;
        for row in rows {
            timeline.push(
                row.map_err(|error| CoreError::Storage(format!("report timeline: {error}")))?,
            );
        }
    }

    let mut limitations = vec![
        "Capture records what was readable when the acquisition ran; every observed omission is listed in the coverage section.".to_string(),
        "Capture metadata events use the application clock. Source timestamps are interpreted only by format parsers and are not part of this report.".to_string(),
        "Absence from a later acquisition is not evidence of deletion, and equal hashes across paths do not prove a copy, move, or hardlink.".to_string(),
        "Alpha reports are unsigned. Verify the acquisition manifest separately; a manifest is not a signature.".to_string(),
    ];
    if coverage.total_gaps() > 0 {
        limitations.push(format!(
            "{} path(s) were not captured. Results are partial for those paths and must not be read as absence.",
            coverage.total_gaps()
        ));
    }

    let unix_seconds = Utc::now().timestamp();
    let report_id = format!("report-{}-{unix_seconds}", acquisition.0);
    Ok(ReportV1 {
        format: REPORT_FORMAT.to_string(),
        report_id,
        created_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        tool_version: context.tool_version.clone(),
        case: CaseView {
            case_id: context.case_id.clone(),
            label: context.label.clone(),
            display_timezone: context.display_timezone.clone(),
        },
        acquisition: AcquisitionView {
            id: acquisition.0,
            method: acquisition.1.clone(),
            claimed_source: acquisition.2.clone(),
            state: acquisition.3,
            link_policy: acquisition.5.clone(),
            roots: roots.clone(),
            started_seconds: acquisition.6,
            ended_seconds: acquisition.7,
        },
        coverage,
        objects,
        timeline,
        provenance: ProvenanceView {
            generated_by: "ghosttrace-cli".to_string(),
            tool_version: context.tool_version.clone(),
            method: acquisition.1,
            claimed_source: acquisition.2,
            link_policy: acquisition.5,
            roots,
            timeline_selection: format!("events limited to {event_limit} in acquisition order"),
            signed: false,
        },
        limitations,
    })
}

/// Publish `report.json` and `report.html` atomically.
pub fn publish(report: &ReportV1, output_dir: &Path) -> CoreResult<PublishedReport> {
    std::fs::create_dir_all(output_dir)
        .map_err(|error| CoreError::Storage(format!("report output dir: {error}")))?;
    let target = output_dir.join(&report.report_id);
    if target.exists() {
        return Err(CoreError::Storage(format!(
            "report {} already exists; refusing to overwrite",
            report.report_id
        )));
    }
    let staging = output_dir.join(format!(".{}.part", report.report_id));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|error| CoreError::Storage(format!("report staging cleanup: {error}")))?;
    }
    let json_text = json::render(report)?;
    let html_text = html::render(report);

    let result = (|| -> CoreResult<()> {
        create_private_dir(&staging)?;
        write_synced(&staging.join("report.json"), json_text.as_bytes())?;
        write_synced(&staging.join("report.html"), html_text.as_bytes())?;
        sync_directory(&staging)?;
        std::fs::rename(&staging, &target)
            .map_err(|error| CoreError::Storage(format!("report publish: {error}")))?;
        sync_directory(output_dir)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    Ok(PublishedReport {
        directory: target.clone(),
        json_path: target.join("report.json"),
        html_path: target.join("report.html"),
    })
}

fn create_private_dir(path: &Path) -> CoreResult<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|error| CoreError::Storage(format!("report staging: {error}")))
}

fn write_synced(path: &Path, bytes: &[u8]) -> CoreResult<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| CoreError::Storage(format!("report file: {error}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| CoreError::Storage(format!("report file: {error}")))
}

fn sync_directory(path: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| CoreError::Storage(format!("report sync: {error}")))?;
    }
    Ok(())
}

fn hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The root descriptor shape stored in `acquisitions.roots_json`.
#[derive(Deserialize)]
struct ManifestRootLike {
    native_path_encoded: String,
}
