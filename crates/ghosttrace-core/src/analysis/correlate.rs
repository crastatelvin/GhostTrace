//! Bounded, explainable relationships between scoped entities (P5.1).
//!
//! Rules embodied here:
//! - Every edge names its rule, rule version, matching field, supporting
//!   events, and the reason its strength is what it is.
//! - A digest match is `observed`: equal complete hashes mean equal bytes, not
//!   a proven copy, move, or common author.
//! - An IP or basename match is only a `candidate`: both are routinely reused
//!   by NAT, DHCP, shared directories, and unrelated files.
//! - Work is bounded three ways (bucket size, pair budget, edge budget) so a
//!   common username or `config.json` cannot turn correlation into an
//!   all-event-pairs scan. Skipped buckets are counted, never hidden.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::params;
use serde_json::json;

use crate::error::{CoreError, CoreResult};
use crate::storage::read::CaseReader;
use crate::storage::writer::{CaseWriter, Param, WriteBatch, WriteOp};

/// Entity cap for one correlation pass. Exceeding it is reported.
pub const MAX_ENTITIES: usize = 100_000;
const MAX_DIGEST_HOLDERS: usize = 200_000;
const SUPPORT_EVENTS: usize = 8;
const MAX_PAGE: u32 = 1_000;

/// Correlation bounds. Defaults are deliberately small enough for an
/// interactive pass over a case of tens of thousands of events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelateConfig {
    /// Candidate rules only compare entities whose event times are this close.
    pub window_seconds: i64,
    /// One bucket larger than this is skipped and reported.
    pub max_bucket_entities: usize,
    /// Pair comparisons allowed in one pass.
    pub max_pairs: usize,
    /// Edges allowed in one pass.
    pub max_edges: usize,
}

impl Default for CorrelateConfig {
    fn default() -> Self {
        Self {
            window_seconds: 3_600,
            max_bucket_entities: 32,
            max_pairs: 50_000,
            max_edges: 5_000,
        }
    }
}

/// One rule version. Ids follow the plan's `domain.name` + explicit version
/// shape, so a changed rule can never overwrite an older explanation.
struct Rule {
    id: &'static str,
    version: &'static str,
    kind: &'static str,
    basis: &'static str,
    windowed: bool,
}

const DIGEST_RULE: Rule = Rule {
    id: "correlate.digest_equal",
    version: "1",
    kind: "observed",
    basis: "equal complete SHA-256 bytes; this does not prove a copy, move, or common origin",
    windowed: false,
};
const IP_RULE: Rule = Rule {
    id: "correlate.shared_ip",
    version: "1",
    kind: "candidate",
    basis: "same claimed IP on different scopes; NAT, DHCP, and proxying make this a candidate only",
    windowed: true,
};
const BASENAME_RULE: Rule = Rule {
    id: "correlate.shared_basename",
    version: "1",
    kind: "candidate",
    basis: "same final path component on different scopes; bytes, owners, and provenance may differ",
    windowed: true,
};
const RULES: &[&Rule] = &[&DIGEST_RULE, &IP_RULE, &BASENAME_RULE];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleReport {
    pub rule_id: &'static str,
    pub rule_version: &'static str,
    pub edges: u64,
    pub buckets_skipped: u64,
    pub unsupported_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelateReport {
    /// Edges this pass derived (before duplicate suppression in storage).
    pub derived: u64,
    /// Rows actually added; a replay of unchanged facts adds none.
    pub inserted: u64,
    pub pairs_examined: u64,
    pub buckets_skipped: u64,
    pub unsupported_time: u64,
    /// True when a bound stopped the pass before it ran out of work.
    pub truncated: bool,
    pub rules: Vec<RuleReport>,
}

struct EntityFacts {
    id: String,
    kind: String,
    raw_form: String,
    first: Option<i64>,
    last: Option<i64>,
}

struct Edge {
    source: String,
    target: String,
    rule: &'static Rule,
    matching: String,
    events: Vec<String>,
}

/// Derive relationships over every recorded entity. Reads only through the
/// shared reader; writes only insert-or-ignore facts.
pub fn correlate(
    writer: &CaseWriter,
    reader: &CaseReader,
    config: &CorrelateConfig,
) -> CoreResult<CorrelateReport> {
    let (facts, facts_truncated) = load_facts(reader)?;
    let by_id: BTreeMap<&str, &EntityFacts> =
        facts.iter().map(|fact| (fact.id.as_str(), fact)).collect();
    let mut deriver = Deriver {
        facts: &by_id,
        reader,
        config,
        edges: Vec::new(),
        seen: BTreeSet::new(),
        counters: RULES
            .iter()
            .map(|rule| {
                (
                    rule.id,
                    RuleReport {
                        rule_id: rule.id,
                        rule_version: rule.version,
                        edges: 0,
                        buckets_skipped: 0,
                        unsupported_time: 0,
                    },
                )
            })
            .collect(),
        pairs_examined: 0,
        truncated: facts_truncated,
    };

    let (holders, holders_truncated) = digest_holders(reader)?;
    deriver.truncated |= holders_truncated;
    let mut digest_buckets: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (path, digest) in &holders {
        digest_buckets
            .entry(digest.clone())
            .or_default()
            .push(path.as_str());
    }
    for (digest, members) in digest_buckets {
        deriver.derive(&DIGEST_RULE, format!("sha256:{digest}"), &members)?;
    }

    let mut ip_buckets: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut basename_buckets: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for fact in facts.iter() {
        match fact.kind.as_str() {
            "ip" => ip_buckets
                .entry(fact.raw_form.as_str())
                .or_default()
                .push(fact.id.as_str()),
            "path" => {
                if let Some(name) = basename(&fact.raw_form) {
                    basename_buckets
                        .entry(name)
                        .or_default()
                        .push(fact.id.as_str());
                }
            }
            _ => {}
        }
    }
    for (ip, members) in ip_buckets {
        deriver.derive(&IP_RULE, format!("ip:{ip}"), &members)?;
    }
    for (name, members) in basename_buckets {
        deriver.derive(&BASENAME_RULE, format!("basename:{name}"), &members)?;
    }

    let inserted = if deriver.edges.is_empty() {
        0
    } else {
        let mut batch = WriteBatch::new();
        for edge in &deriver.edges {
            batch = batch.push(WriteOp::fact(
                "relationships",
                vec![
                    "source_entity_id",
                    "target_entity_id",
                    "kind",
                    "rule_id",
                    "rule_version",
                    "support_json",
                    "strength_basis",
                ],
                vec![
                    Param::Text(edge.source.clone()),
                    Param::Text(edge.target.clone()),
                    Param::Text(edge.rule.kind.to_string()),
                    Param::Text(edge.rule.id.to_string()),
                    Param::Text(edge.rule.version.to_string()),
                    Param::Text(
                        json!({
                            "matching_fields": [edge.matching],
                            "events": edge.events,
                        })
                        .to_string(),
                    ),
                    Param::Text(edge.rule.basis.to_string()),
                ],
            ));
        }
        writer.execute(batch)?.applied as u64
    };

    let mut rules: Vec<RuleReport> = deriver.counters.into_values().collect();
    rules.sort_by_key(|rule| rule.rule_id);
    Ok(CorrelateReport {
        derived: deriver.edges.len() as u64,
        inserted,
        pairs_examined: deriver.pairs_examined as u64,
        buckets_skipped: rules.iter().map(|rule| rule.buckets_skipped).sum(),
        unsupported_time: rules.iter().map(|rule| rule.unsupported_time).sum(),
        truncated: deriver.truncated,
        rules,
    })
}

struct Deriver<'a> {
    facts: &'a BTreeMap<&'a str, &'a EntityFacts>,
    reader: &'a CaseReader,
    config: &'a CorrelateConfig,
    edges: Vec<Edge>,
    seen: BTreeSet<(String, String, &'static str)>,
    counters: BTreeMap<&'static str, RuleReport>,
    pairs_examined: usize,
    truncated: bool,
}

impl Deriver<'_> {
    fn derive(
        &mut self,
        rule: &'static Rule,
        matching: String,
        members: &[&str],
    ) -> CoreResult<()> {
        let mut members: Vec<&str> = members.to_vec();
        members.sort_unstable();
        members.dedup();
        if members.len() < 2 {
            return Ok(());
        }
        if members.len() > self.config.max_bucket_entities {
            if let Some(counter) = self.counters.get_mut(rule.id) {
                counter.buckets_skipped += 1;
            }
            return Ok(());
        }
        let mut edges = 0_u64;
        let mut unsupported_time = 0_u64;
        'pairs: for i in 0..members.len() {
            for other in members.iter().skip(i + 1) {
                if self.pairs_examined >= self.config.max_pairs
                    || self.edges.len() >= self.config.max_edges
                {
                    self.truncated = true;
                    break 'pairs;
                }
                let (Some(left), Some(right)) =
                    (self.facts.get(members[i]), self.facts.get(*other))
                else {
                    continue;
                };
                self.pairs_examined += 1;
                if rule.windowed {
                    match within_window(left, right, self.config.window_seconds) {
                        None => {
                            unsupported_time += 1;
                            continue;
                        }
                        Some(false) => continue,
                        Some(true) => {}
                    }
                }
                let (source, target) = if left.id <= right.id {
                    (left.id.clone(), right.id.clone())
                } else {
                    (right.id.clone(), left.id.clone())
                };
                if !self.seen.insert((source.clone(), target.clone(), rule.id)) {
                    continue;
                }
                self.edges.push(Edge {
                    events: support_events(self.reader, &source, &target)?,
                    source,
                    target,
                    rule,
                    matching: matching.clone(),
                });
                edges += 1;
            }
        }
        if let Some(counter) = self.counters.get_mut(rule.id) {
            counter.edges += edges;
            counter.unsupported_time += unsupported_time;
        }
        Ok(())
    }
}

/// `None` means one side has no resolved time, so the window cannot be
/// evaluated. That is reported, never treated as "outside the window".
fn within_window(left: &EntityFacts, right: &EntityFacts, window: i64) -> Option<bool> {
    let (Some(left_first), Some(left_last)) = (left.first, left.last) else {
        return None;
    };
    let (Some(right_first), Some(right_last)) = (right.first, right.last) else {
        return None;
    };
    let gap = if left_last < right_first {
        right_first - left_last
    } else if right_last < left_first {
        left_first - right_last
    } else {
        0
    };
    Some(gap <= window)
}

fn load_facts(reader: &CaseReader) -> CoreResult<(Vec<EntityFacts>, bool)> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT n.id, n.kind, n.raw_form, MIN(e.chosen_seconds), MAX(e.chosen_seconds)
             FROM entities n
             LEFT JOIN event_entities ee ON ee.entity_id = n.id
             LEFT JOIN events e ON e.id = ee.event_id
             WHERE n.kind IN ('path', 'ip')
             GROUP BY n.id
             ORDER BY n.id
             LIMIT ?1",
        )
        .map_err(|error| CoreError::Storage(format!("prepare entity buckets: {error}")))?;
    let mut rows = statement
        .query(params![(MAX_ENTITIES + 1) as i64])
        .map_err(|error| CoreError::Storage(format!("read entity buckets: {error}")))?;
    let mut facts = Vec::new();
    let mut truncated = false;
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read entity bucket: {error}")))?
    {
        if facts.len() == MAX_ENTITIES {
            truncated = true;
            break;
        }
        facts.push(EntityFacts {
            id: row.get(0).map_err(storage_error)?,
            kind: row.get(1).map_err(storage_error)?,
            raw_form: row.get(2).map_err(storage_error)?,
            first: row.get(3).map_err(storage_error)?,
            last: row.get(4).map_err(storage_error)?,
        });
    }
    Ok((facts, truncated))
}

/// Path entities that share an event with a digest entity. This is an indexed
/// join on `event_entities`, never a comparison of every event pair.
fn digest_holders(reader: &CaseReader) -> CoreResult<(Vec<(String, String)>, bool)> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT DISTINCT p.id, d.raw_form
             FROM event_entities pd
             JOIN event_entities dd ON dd.event_id = pd.event_id
             JOIN entities p ON p.id = pd.entity_id AND p.kind = 'path'
             JOIN entities d ON d.id = dd.entity_id AND d.kind = 'digest'
             ORDER BY d.raw_form, p.id
             LIMIT ?1",
        )
        .map_err(|error| CoreError::Storage(format!("prepare digest buckets: {error}")))?;
    let mut rows = statement
        .query(params![(MAX_DIGEST_HOLDERS + 1) as i64])
        .map_err(|error| CoreError::Storage(format!("read digest buckets: {error}")))?;
    let mut holders = Vec::new();
    let mut truncated = false;
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read digest holder: {error}")))?
    {
        if holders.len() == MAX_DIGEST_HOLDERS {
            truncated = true;
            break;
        }
        holders.push((
            row.get(0).map_err(storage_error)?,
            row.get(1).map_err(storage_error)?,
        ));
    }
    Ok((holders, truncated))
}

fn support_events(reader: &CaseReader, source: &str, target: &str) -> CoreResult<Vec<String>> {
    let mut statement = reader
        .connection()
        .prepare(
            "SELECT DISTINCT event_id FROM event_entities
             WHERE entity_id IN (?1, ?2)
             ORDER BY event_id
             LIMIT ?3",
        )
        .map_err(|error| CoreError::Storage(format!("prepare edge support: {error}")))?;
    let mut rows = statement
        .query(params![source, target, SUPPORT_EVENTS as i64])
        .map_err(|error| CoreError::Storage(format!("read edge support: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read edge support row: {error}")))?
    {
        events.push(row.get(0).map_err(storage_error)?);
    }
    Ok(events)
}

/// Final component of a recorded path, treating both separators as boundaries.
fn basename(path: &str) -> Option<String> {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    (!name.is_empty() && name != path).then(|| name.to_string())
}

/// Bounded, keyset-paginated relationship read (plan P5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipQuery {
    /// Return edges with this entity on either endpoint.
    pub entity_id: Option<String>,
    pub kind: Option<String>,
    pub rule_id: Option<String>,
    pub limit: u32,
    pub after_id: Option<i64>,
}

impl Default for RelationshipQuery {
    fn default() -> Self {
        Self {
            entity_id: None,
            kind: None,
            rule_id: None,
            limit: 200,
            after_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRef {
    pub id: String,
    pub kind: String,
    pub scoped_identity: String,
    pub display_form: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipRow {
    pub id: i64,
    pub kind: String,
    pub rule_id: String,
    pub rule_version: String,
    pub source: EntityRef,
    pub target: EntityRef,
    /// Stored support JSON: matching fields and supporting event ids.
    pub support_json: String,
    pub strength_basis: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationshipPage {
    pub rows: Vec<RelationshipRow>,
    pub next_cursor: Option<i64>,
}

pub fn query_relationships(
    reader: &CaseReader,
    query: &RelationshipQuery,
) -> CoreResult<RelationshipPage> {
    let limit = query.limit.clamp(1, MAX_PAGE) as i64;
    let mut sql = String::from(
        "SELECT r.id, r.kind, r.rule_id, r.rule_version, r.support_json, r.strength_basis,
                s.id, s.kind, s.scoped_identity, s.display_form,
                t.id, t.kind, t.scoped_identity, t.display_form
         FROM relationships r
         JOIN entities s ON s.id = r.source_entity_id
         JOIN entities t ON t.id = r.target_entity_id
         WHERE r.id > ?",
    );
    let mut values: Vec<rusqlite::types::Value> =
        vec![rusqlite::types::Value::Integer(query.after_id.unwrap_or(0))];
    if let Some(entity) = &query.entity_id {
        sql.push_str(" AND (r.source_entity_id = ? OR r.target_entity_id = ?)");
        values.push(rusqlite::types::Value::Text(entity.clone()));
        values.push(rusqlite::types::Value::Text(entity.clone()));
    }
    if let Some(kind) = &query.kind {
        sql.push_str(" AND r.kind = ?");
        values.push(rusqlite::types::Value::Text(kind.clone()));
    }
    if let Some(rule) = &query.rule_id {
        sql.push_str(" AND r.rule_id = ?");
        values.push(rusqlite::types::Value::Text(rule.clone()));
    }
    sql.push_str(" ORDER BY r.id LIMIT ?");
    values.push(rusqlite::types::Value::Integer(limit + 1));

    let mut statement = reader
        .connection()
        .prepare(&sql)
        .map_err(|error| CoreError::Storage(format!("prepare relationship query: {error}")))?;
    let mut rows = statement
        .query(rusqlite::params_from_iter(values.iter()))
        .map_err(|error| CoreError::Storage(format!("read relationships: {error}")))?;
    let mut page = RelationshipPage {
        rows: Vec::new(),
        next_cursor: None,
    };
    while let Some(row) = rows
        .next()
        .map_err(|error| CoreError::Storage(format!("read relationship: {error}")))?
    {
        if page.rows.len() as i64 == limit {
            page.next_cursor = page.rows.last().map(|row: &RelationshipRow| row.id);
            break;
        }
        page.rows.push(RelationshipRow {
            id: row.get(0).map_err(storage_error)?,
            kind: row.get(1).map_err(storage_error)?,
            rule_id: row.get(2).map_err(storage_error)?,
            rule_version: row.get(3).map_err(storage_error)?,
            support_json: row.get(4).map_err(storage_error)?,
            strength_basis: row.get(5).map_err(storage_error)?,
            source: EntityRef {
                id: row.get(6).map_err(storage_error)?,
                kind: row.get(7).map_err(storage_error)?,
                scoped_identity: row.get(8).map_err(storage_error)?,
                display_form: row.get(9).map_err(storage_error)?,
            },
            target: EntityRef {
                id: row.get(10).map_err(storage_error)?,
                kind: row.get(11).map_err(storage_error)?,
                scoped_identity: row.get(12).map_err(storage_error)?,
                display_form: row.get(13).map_err(storage_error)?,
            },
        });
    }
    Ok(page)
}

fn storage_error(error: rusqlite::Error) -> CoreError {
    CoreError::Storage(format!("read relationship field: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(id: &str, first: Option<i64>, last: Option<i64>) -> EntityFacts {
        EntityFacts {
            id: id.to_string(),
            kind: "ip".to_string(),
            raw_form: "10.0.0.6".to_string(),
            first,
            last,
        }
    }

    #[test]
    fn windows_are_inclusive_and_missing_time_is_not_a_match() {
        let a = facts("a", Some(0), Some(10));
        let b = facts("b", Some(3_590), Some(3_600));
        assert_eq!(within_window(&a, &b, 3_600), Some(true));
        assert_eq!(within_window(&a, &b, 1), Some(false));
        assert_eq!(within_window(&a, &facts("c", None, None), 1), None);
    }

    #[test]
    fn basenames_are_taken_from_either_separator() {
        assert_eq!(
            basename("/etc/app/config.json").as_deref(),
            Some("config.json")
        );
        assert_eq!(
            basename("C:\\Users\\bob\\config.json").as_deref(),
            Some("config.json")
        );
        assert_eq!(basename("config.json"), None, "no directory component");
        assert_eq!(basename("/etc/"), None);
    }
}
