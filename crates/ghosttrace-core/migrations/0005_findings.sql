-- 0005_findings: explainable findings, analyst review history, and saved
-- views (P5.2). Additive only.

-- Per-rule counts and "not evaluated" reasons for one analysis run. Findings
-- carry their own rows; this column explains how many were produced and what
-- the evaluator excluded.
ALTER TABLE analysis_runs ADD COLUMN counts_json TEXT NOT NULL DEFAULT '{}';

-- Adapter-mapped structured fields, kept apart from the raw record. The syslog
-- adapter can map an authentication outcome to a scoped account and service;
-- storing that interpretation next to (not inside) `raw_fields_json` keeps the
-- recorded bytes and the interpretation distinguishable. NULL means the
-- adapter mapped nothing, never "mapped and empty".
ALTER TABLE raw_observations ADD COLUMN mapped_fields_json TEXT;

-- Findings are read by run and by rule; the primary key is the finding id.
-- 0001 already has `findings_by_run` over (run, severity, disposition), so this
-- second run index uses a different name to actually be created.
CREATE INDEX IF NOT EXISTS findings_by_run_rule ON findings(analysis_run_id, rule_id);
CREATE INDEX IF NOT EXISTS findings_by_rule ON findings(rule_id, rule_version, id);

-- Annotation history is read newest-first for one target. Revisions are
-- append-only: an edit never rewrites an earlier note.
CREATE INDEX IF NOT EXISTS annotation_revisions_by_target
    ON annotation_revisions(target_id, id);

-- Saved filters are named, bounded value sets validated against the query
-- contract on write and on read. No SQL or arbitrary JSON reaches execution.
CREATE TABLE IF NOT EXISTS saved_views (
    name TEXT PRIMARY KEY NOT NULL,
    filter_json TEXT NOT NULL,
    created_seconds INTEGER NOT NULL
);
