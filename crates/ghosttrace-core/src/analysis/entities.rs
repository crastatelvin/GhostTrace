//! Scoped entity resolution over recorded events (plan Section 11, P5.1).
//!
//! Rules embodied here:
//! - Identity is scoped before it is compared. A PID means nothing without its
//!   host and boot, a path means nothing without its acquisition, and only a
//!   complete byte digest is global because equal bytes are equal bytes.
//! - Only documented adapter fields become entities. Free text is never parsed
//!   into an identity, so a log message cannot invent a user, a host, or an IP.
//! - Replaying a build is idempotent: entity ids are derived from kind, scope,
//!   and raw form, and every write is an insert-or-ignore fact.
//!
//! Events recorded before migration 0004 carry no source link. They still
//! contribute the facts that live on the event row (the host claim), and the
//! report counts them so "not analysed" never reads as "analysed and empty".

use std::collections::BTreeSet;

use rusqlite::params;
use serde_json::Value;

use crate::domain::path::{NativePath, NativePathWire};
use crate::error::{CoreError, CoreResult};
use crate::integrity::hash::{identity_hex, sha256_hex};
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};

/// Rule set identity recorded with derived entities (plan Section 11).
pub const RULES_ID: &str = "entities";
pub const RULES_VERSION: &str = "1";

/// Hard cap on one build. Exceeding it is reported, never silently dropped.
pub const MAX_EVENTS: usize = 200_000;
const FLUSH_LINKS: usize = 2_000;
const MAX_FIELD_CHARS: usize = 512;
const MAX_PATH_CHARS: usize = 4_096;

/// Entity classes the adapters can support without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntityKind {
    Host,
    User,
    Ip,
    Process,
    Path,
    Digest,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Host => "host",
            EntityKind::User => "user",
            EntityKind::Ip => "ip",
            EntityKind::Process => "process",
            EntityKind::Path => "path",
            EntityKind::Digest => "digest",
        }
    }
}

/// Outcome of one build. Counts are read back from storage, so a replay
/// reports the stored truth rather than the number of write attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityBuildReport {
    pub run_id: String,
    pub events: u64,
    pub events_without_source: u64,
    pub entities: u64,
    pub links: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EntityRow {
    id: String,
    kind: EntityKind,
    scoped_identity: String,
    raw_form: String,
    display_form: String,
}

impl EntityRow {
    fn new(
        kind: EntityKind,
        components: Vec<String>,
        raw_form: String,
        display_form: String,
    ) -> Self {
        let scoped_identity =
            serde_json::to_string(&components).expect("a vector of strings always serializes");
        let id = format!(
            "ent-{}",
            identity_hex(
                &format!("{}|{}|{}", kind.as_str(), scoped_identity, raw_form),
                24
            )
        );
        Self {
            id,
            kind,
            scoped_identity,
            raw_form,
            display_form,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LinkRow {
    event_id: String,
    entity_id: String,
    role: &'static str,
}

struct EventRow {
    event_id: String,
    event_kind: String,
    host_claim: Option<String>,
    evidence_id: Option<String>,
    raw_fields: Option<String>,
    mapped_fields: Option<String>,
    path_kind: Option<String>,
    path_encoded: Option<String>,
    digest: Option<Vec<u8>>,
    digest_status: Option<String>,
}

/// Resolve entities for one parse run and link them to that run's events.
/// The unit is the run, not the display revision: capture runs keep their own
/// revision label while still being analyzable.
pub fn build_entities(
    writer: &CaseWriter,
    reader: &CaseReader,
    run_id: &str,
) -> CoreResult<EntityBuildReport> {
    let acquisition: String = reader
        .connection()
        .query_row(
            "SELECT acquisition_id FROM parse_runs WHERE id = ?1",
            params![run_id],
            |row| row.get(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                CoreError::InvalidInput(format!("unknown parse run: {run_id}"))
            }
            other => CoreError::Storage(format!("read parse run: {other}")),
        })?;

    let mut report = EntityBuildReport {
        run_id: run_id.to_string(),
        events: 0,
        events_without_source: 0,
        entities: 0,
        links: 0,
        truncated: false,
    };
    let mut entities: BTreeSet<EntityRow> = BTreeSet::new();
    let mut links: BTreeSet<LinkRow> = BTreeSet::new();
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT e.id, e.kind, e.host_claim, e.evidence_id, r.raw_fields_json,
                    r.mapped_fields_json,
                    o.native_path_kind, o.native_path_encoded, o.sha256, o.digest_status
             FROM events e
             LEFT JOIN raw_observations r
               ON r.parse_run_id = e.parse_run_id
              AND r.evidence_id = e.evidence_id
              AND r.locator_identity = e.locator_identity
             LEFT JOIN evidence_objects o ON o.id = e.evidence_id
             WHERE e.parse_run_id = ?1
             ORDER BY e.rowid
             LIMIT ?2",
        )
        .map_err(|error| CoreError::Storage(format!("prepare entity scan: {error}")))?;
    let mut rows = statement
        .query(params![run_id, (MAX_EVENTS + 1) as i64])
        .map_err(|error| CoreError::Storage(format!("scan entity events: {error}")))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read entity event: {error}")))?
    {
        if report.events as usize >= MAX_EVENTS {
            report.truncated = true;
            break;
        }
        let observed = EventRow {
            event_id: row.get(0).map_err(storage_error)?,
            event_kind: row.get(1).map_err(storage_error)?,
            host_claim: row.get(2).map_err(storage_error)?,
            evidence_id: row.get(3).map_err(storage_error)?,
            raw_fields: row.get(4).map_err(storage_error)?,
            mapped_fields: row.get(5).map_err(storage_error)?,
            path_kind: row.get(6).map_err(storage_error)?,
            path_encoded: row.get(7).map_err(storage_error)?,
            digest: row.get(8).map_err(storage_error)?,
            digest_status: row.get(9).map_err(storage_error)?,
        };
        report.events += 1;
        if observed.evidence_id.is_none() {
            report.events_without_source += 1;
        }
        for entity in entities_for(&observed, &acquisition) {
            links.insert(LinkRow {
                event_id: observed.event_id.clone(),
                entity_id: entity.id.clone(),
                role: entity.kind.as_str(),
            });
            entities.insert(entity);
        }
        if links.len() >= FLUSH_LINKS {
            flush(writer, &mut entities, &mut links)?;
        }
    }
    flush(writer, &mut entities, &mut links)?;

    let (links, entities) = reader
        .connection()
        .query_row(
            "SELECT count(*), count(DISTINCT ee.entity_id)
             FROM event_entities ee
             JOIN events e ON e.id = ee.event_id
             WHERE e.parse_run_id = ?1",
            params![run_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|error| CoreError::Storage(format!("count entities: {error}")))?;
    report.links = links.max(0) as u64;
    report.entities = entities.max(0) as u64;
    Ok(report)
}

fn flush(
    writer: &CaseWriter,
    entities: &mut BTreeSet<EntityRow>,
    links: &mut BTreeSet<LinkRow>,
) -> CoreResult<()> {
    if entities.is_empty() && links.is_empty() {
        return Ok(());
    }
    let mut batch = WriteBatch::new();
    for entity in entities.iter() {
        batch = batch.push(WriteOp::fact(
            "entities",
            vec!["id", "kind", "scoped_identity", "raw_form", "display_form"],
            vec![
                Param::Text(entity.id.clone()),
                Param::Text(entity.kind.as_str().to_string()),
                Param::Text(entity.scoped_identity.clone()),
                Param::Text(entity.raw_form.clone()),
                Param::Text(entity.display_form.clone()),
            ],
        ));
    }
    for link in links.iter() {
        batch = batch.push(WriteOp::fact(
            "event_entities",
            vec!["event_id", "entity_id", "role"],
            vec![
                Param::Text(link.event_id.clone()),
                Param::Text(link.entity_id.clone()),
                Param::Text(link.role.to_string()),
            ],
        ));
    }
    writer.execute(batch)?;
    entities.clear();
    links.clear();
    Ok(())
}

/// Everything an event can support as an identity. Field names are the
/// documented adapter fields, never text matched out of a message.
fn entities_for(row: &EventRow, acquisition: &str) -> Vec<EntityRow> {
    let mut found = Vec::new();
    let host = row
        .host_claim
        .as_deref()
        .and_then(|value| clean(value, MAX_FIELD_CHARS));
    if let Some(host) = &host {
        found.push(EntityRow::new(
            EntityKind::Host,
            vec!["host".into(), "claim".into(), host.clone()],
            host.clone(),
            host.clone(),
        ));
    }
    let host_scope = host.unwrap_or_else(|| "unscoped".to_string());
    let raw = row
        .raw_fields
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    let mapped = row
        .mapped_fields
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok());
    {
        // Adapter-mapped fields (an explicit interpretation) win over raw
        // fields; raw fields are the fallback, never free text.
        let field = |names: &[&str], limit: usize| {
            mapped
                .as_ref()
                .and_then(|fields| first_field(fields, names, limit))
                .or_else(|| {
                    raw.as_ref()
                        .and_then(|fields| first_field(fields, names, limit))
                })
        };
        if let Some(user) = field(USER_FIELDS, MAX_FIELD_CHARS) {
            found.push(EntityRow::new(
                EntityKind::User,
                vec![
                    "host".into(),
                    host_scope.clone(),
                    "user".into(),
                    user.clone(),
                ],
                user.clone(),
                user,
            ));
        }
        if let Some(ip) = field(IP_FIELDS, MAX_FIELD_CHARS) {
            found.push(EntityRow::new(
                EntityKind::Ip,
                vec!["host".into(), host_scope.clone(), "ip".into(), ip.clone()],
                ip.clone(),
                ip,
            ));
        }
        if let Some(pid) = field(PID_FIELDS, MAX_FIELD_CHARS)
            && pid.bytes().all(|byte| byte.is_ascii_digit())
        {
            let boot = field(BOOT_FIELDS, MAX_FIELD_CHARS).unwrap_or_else(|| "no-boot".to_string());
            found.push(EntityRow::new(
                EntityKind::Process,
                vec![
                    "host".into(),
                    host_scope.clone(),
                    "process".into(),
                    boot,
                    pid.clone(),
                ],
                pid.clone(),
                pid,
            ));
        }
        if let Some(path) = field(PATH_FIELDS, MAX_PATH_CHARS) {
            found.push(EntityRow::new(
                EntityKind::Path,
                vec![
                    "acquisition".into(),
                    acquisition.to_string(),
                    "path".into(),
                    path.clone(),
                ],
                path.clone(),
                path,
            ));
        }
        if let Some(digest) = field(DIGEST_FIELDS, 128).as_deref().and_then(digest_value) {
            found.push(digest_entity(&digest));
        }
    }
    // Captured files carry their exact path and complete digest on the object.
    if row.event_kind == "file.observed" {
        if let (Some(kind), Some(encoded)) = (&row.path_kind, &row.path_encoded) {
            found.push(EntityRow::new(
                EntityKind::Path,
                vec![
                    "acquisition".into(),
                    acquisition.to_string(),
                    "path".into(),
                    encoded.clone(),
                ],
                encoded.clone(),
                display_path(kind, encoded),
            ));
        }
        if let (Some(status), Some(digest)) = (&row.digest_status, &row.digest)
            && status == "complete"
            && digest.len() == 32
        {
            let mut bytes = [0_u8; 32];
            bytes.copy_from_slice(digest);
            found.push(digest_entity(&sha256_hex(&bytes)));
        }
    }
    found
}

fn digest_entity(digest: &str) -> EntityRow {
    EntityRow::new(
        EntityKind::Digest,
        vec!["sha256".into(), digest.to_string()],
        digest.to_string(),
        digest.to_string(),
    )
}

const USER_FIELDS: &[&str] = &["user", "username", "account", "user.name"];
const IP_FIELDS: &[&str] = &["src_ip", "remote_ip", "source_ip", "ip"];
const PID_FIELDS: &[&str] = &["pid", "_PID", "process_id"];
const BOOT_FIELDS: &[&str] = &["_BOOT_ID", "boot_id", "boot"];
const PATH_FIELDS: &[&str] = &["path", "current_path", "target_path"];
const DIGEST_FIELDS: &[&str] = &["sha256", "sha256_hex", "hash"];

fn first_field(fields: &Value, names: &[&str], limit: usize) -> Option<String> {
    names.iter().find_map(|name| {
        field(fields, name)
            .and_then(value_text)
            .and_then(|text| clean(&text, limit))
    })
}

/// Object fields (JSONL, browser rows, syslog headers) and journal pair arrays
/// are the two recorded shapes. Anything else yields nothing.
fn field<'a>(fields: &'a Value, name: &str) -> Option<&'a Value> {
    match fields {
        Value::Object(map) => map.get(name),
        Value::Array(pairs) => pairs.iter().find_map(|pair| {
            let pair = pair.as_array()?;
            (pair.len() == 2 && pair[0].as_str() == Some(name)).then(|| &pair[1])
        }),
        _ => None,
    }
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn clean(text: &str, limit: usize) -> Option<String> {
    if text.is_empty() || text.len() > limit || text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_string())
}

fn digest_value(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    (lower.len() == 64 && lower.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(lower)
}

fn display_path(kind: &str, encoded: &str) -> String {
    NativePath::try_from(NativePathWire {
        kind: kind.to_string(),
        encoded: encoded.to_string(),
    })
    .map(|path| path.display())
    .unwrap_or_else(|_| encoded.to_string())
}

fn storage_error(error: rusqlite::Error) -> CoreError {
    CoreError::Storage(format!("read entity event field: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_components_distinguish_same_pid_on_different_hosts_and_boots() {
        let a = EntityRow::new(
            EntityKind::Process,
            vec![
                "host".into(),
                "edge-a".into(),
                "process".into(),
                "boot-1".into(),
                "42".into(),
            ],
            "42".into(),
            "42".into(),
        );
        let b = EntityRow::new(
            EntityKind::Process,
            vec![
                "host".into(),
                "edge-b".into(),
                "process".into(),
                "boot-1".into(),
                "42".into(),
            ],
            "42".into(),
            "42".into(),
        );
        let c = EntityRow::new(
            EntityKind::Process,
            vec![
                "host".into(),
                "edge-a".into(),
                "process".into(),
                "boot-2".into(),
                "42".into(),
            ],
            "42".into(),
            "42".into(),
        );
        assert_ne!(a.id, b.id);
        assert_ne!(a.id, c.id);
        assert_eq!(a.id, a.clone().id, "ids are deterministic");
    }

    #[test]
    fn digests_require_exactly_64_hex_characters() {
        assert!(digest_value(&"a".repeat(64)).is_some());
        assert!(digest_value(&"A".repeat(64)).is_some());
        assert!(digest_value(&"a".repeat(63)).is_none());
        assert!(digest_value(&format!("{} ", "a".repeat(64))).is_none());
        assert!(digest_value(&"g".repeat(64)).is_none());
    }

    #[test]
    fn journal_pair_arrays_and_objects_both_expose_fields() {
        let object = serde_json::json!({ "user": "alice" });
        let pairs = serde_json::json!([["_PID", "42"], ["_BOOT_ID", "boot-1"]]);
        assert_eq!(
            first_field(&object, USER_FIELDS, 32).as_deref(),
            Some("alice")
        );
        assert_eq!(first_field(&pairs, PID_FIELDS, 32).as_deref(), Some("42"));
    }
}
