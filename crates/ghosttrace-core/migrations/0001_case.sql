-- 0001_case: base case schema (plan Sections 5, 8).
--
-- Rules embodied here:
-- - opaque application-generated IDs are TEXT; deterministic source-locator
--   identity is stored separately and is the idempotency key material;
-- - foreign keys reject dangling references (enforced at runtime too);
-- - normalized times are signed Unix seconds + integer nanoseconds; a NULL
--   chosen time means unresolved and lives in the explicit unresolved view;
-- - large raw integers are TEXT decimal, never lossy numbers;
-- - no application data is deleted by schema code; migrations are additive.

PRAGMA foreign_keys = ON;

CREATE TABLE cases (
    id TEXT PRIMARY KEY NOT NULL,
    label TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_seconds INTEGER NOT NULL,
    display_timezone TEXT NOT NULL DEFAULT 'UTC',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE acquisitions (
    id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES cases(id),
    method TEXT NOT NULL CHECK (method IN ('protected_copy','live_best_effort')),
    claimed_source TEXT NOT NULL,
    roots_json TEXT NOT NULL DEFAULT '[]',
    link_policy TEXT NOT NULL DEFAULT 'no_follow',
    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','partial','cancelled','failed')),
    started_seconds INTEGER,
    ended_seconds INTEGER,
    tool_version TEXT NOT NULL DEFAULT ''
);

CREATE TABLE coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    acquisition_id TEXT NOT NULL REFERENCES acquisitions(id),
    path_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('captured','excluded','inaccessible','unstable','vanished','unsupported','unobserved')),
    error_code TEXT,
    attempts INTEGER NOT NULL DEFAULT 1,
    scope TEXT NOT NULL DEFAULT 'file'
);
CREATE UNIQUE INDEX coverage_identity ON coverage(acquisition_id, path_key, scope);

CREATE TABLE evidence_objects (
    id TEXT PRIMARY KEY NOT NULL,
    acquisition_id TEXT NOT NULL REFERENCES acquisitions(id),
    native_path_kind TEXT NOT NULL CHECK (native_path_kind IN ('unix','windows')),
    native_path_encoded TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('file_content','non_file_observation')),
    byte_length INTEGER,
    digest_status TEXT NOT NULL CHECK (digest_status IN ('not_applicable','complete','partial','failed')),
    sha256 BLOB,
    object_location TEXT
);
CREATE INDEX objects_by_digest ON evidence_objects(sha256, digest_status);

-- One acquisition scopes native identity; device/file IDs are never global.
CREATE TABLE file_observations (
    id TEXT PRIMARY KEY NOT NULL,
    acquisition_id TEXT NOT NULL REFERENCES acquisitions(id),
    evidence_id TEXT REFERENCES evidence_objects(id),
    scoped_identity TEXT,
    size INTEGER,
    link_target_encoded TEXT,
    link_target_kind TEXT,
    observed_seconds INTEGER,
    observed_nanos INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX file_obs_by_identity ON file_observations(acquisition_id, scoped_identity);

CREATE TABLE parse_runs (
    id TEXT PRIMARY KEY NOT NULL,
    acquisition_id TEXT NOT NULL REFERENCES acquisitions(id),
    parser_id TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    config_digest TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','partial','cancelled','failed')),
    counts_json TEXT NOT NULL DEFAULT '{}',
    diagnostics_json TEXT NOT NULL DEFAULT '[]'
);

-- acquisition + evidence + parser version/config + exact locator = identity.
CREATE TABLE raw_observations (
    id TEXT PRIMARY KEY NOT NULL,
    parse_run_id TEXT NOT NULL REFERENCES parse_runs(id),
    acquisition_id TEXT NOT NULL REFERENCES acquisitions(id),
    evidence_id TEXT NOT NULL REFERENCES evidence_objects(id),
    locator_kind TEXT NOT NULL CHECK (locator_kind IN ('byte_range','logical_row','binary_record','filesystem_entry')),
    locator_identity TEXT NOT NULL,
    raw_fields_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (acquisition_id, evidence_id, parse_run_id, locator_identity)
);
CREATE INDEX raw_obs_by_evidence ON raw_observations(evidence_id, locator_identity);

CREATE TABLE events (
    id TEXT PRIMARY KEY NOT NULL,
    revision TEXT NOT NULL,
    parse_run_id TEXT NOT NULL REFERENCES parse_runs(id),
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    host_claim TEXT,
    chosen_seconds INTEGER,
    chosen_nanos INTEGER NOT NULL DEFAULT 0,
    time_status TEXT NOT NULL CHECK (time_status IN ('resolved','ambiguous','unresolved','invalid')),
    UNIQUE (revision, id)
);
-- Keyset pagination and filters plan (Section 8): active revision, chosen
-- time, then id for a total order; host/source/kind secondary access.
CREATE INDEX events_by_time_keyset ON events(revision, chosen_seconds, chosen_nanos, id);
CREATE INDEX events_by_host_kind ON events(revision, host_claim, kind);
-- The unresolved view: unresolved and ambiguous-but-unchosen times are
-- reachable, never silently dropped.
CREATE INDEX events_unresolved ON events(revision, time_status, id);

CREATE TABLE event_times (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    semantic TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('resolved','ambiguous','unresolved','invalid')),
    -- candidates as JSON (exact seconds + nanos pairs)
    candidates_json TEXT NOT NULL DEFAULT '[]',
    raw_field TEXT,
    raw_value_kind TEXT CHECK (raw_value_kind IN ('integer','text')),
    -- raw integer is exact TEXT decimal; never a lossy float
    raw_value_text TEXT,
    raw_text TEXT,
    epoch TEXT NOT NULL,
    unit TEXT NOT NULL,
    declared_precision TEXT NOT NULL,
    clock_domain TEXT NOT NULL,
    assumptions_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (event_id, name)
);

CREATE TABLE entities (
    id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    scoped_identity TEXT NOT NULL,
    raw_form TEXT NOT NULL,
    display_form TEXT NOT NULL,
    UNIQUE (kind, scoped_identity, raw_form)
);

CREATE TABLE event_entities (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL REFERENCES entities(id),
    role TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (event_id, entity_id, role)
);

CREATE TABLE relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_entity_id TEXT NOT NULL REFERENCES entities(id),
    target_entity_id TEXT NOT NULL REFERENCES entities(id),
    kind TEXT NOT NULL CHECK (kind IN ('observed','candidate')),
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    support_json TEXT NOT NULL DEFAULT '[]',
    strength_basis TEXT NOT NULL DEFAULT ''
);
CREATE INDEX relationship_endpoints ON relationships(source_entity_id, target_entity_id, kind);

CREATE TABLE analysis_runs (
    id TEXT PRIMARY KEY NOT NULL,
    input_revision TEXT NOT NULL,
    rules_id TEXT NOT NULL,
    rules_version TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','partial','cancelled','failed')),
    time_adjustments_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY NOT NULL,
    analysis_run_id TEXT NOT NULL REFERENCES analysis_runs(id),
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    event_ids_json TEXT NOT NULL DEFAULT '[]',
    predicates_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL,
    rationale TEXT NOT NULL,
    alternatives_json TEXT NOT NULL DEFAULT '[]',
    disposition TEXT NOT NULL DEFAULT 'undismissed'
);
CREATE INDEX findings_by_run ON findings(analysis_run_id, severity, disposition);

CREATE TABLE annotation_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id TEXT NOT NULL,
    author_label TEXT NOT NULL,
    created_seconds INTEGER NOT NULL,
    previous_revision INTEGER REFERENCES annotation_revisions(id),
    text TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    disposition TEXT
);

CREATE TABLE export_runs (
    id TEXT PRIMARY KEY NOT NULL,
    input_revision TEXT NOT NULL,
    redaction_profile TEXT NOT NULL DEFAULT 'none',
    files_json TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','partial','cancelled','failed')),
    manifest_ids_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE job_checkpoints (
    job_id TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued','running','completed','partial','cancelled','failed')),
    input_identity TEXT NOT NULL DEFAULT '',
    input_digest TEXT NOT NULL DEFAULT '',
    adapter_version TEXT NOT NULL DEFAULT '',
    config_digest TEXT NOT NULL DEFAULT '',
    committed_locator TEXT,
    counters_json TEXT NOT NULL DEFAULT '{}',
    updated_seconds INTEGER NOT NULL
);

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_seconds INTEGER NOT NULL
);
