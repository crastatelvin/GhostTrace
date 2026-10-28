-- 0003_search: full-text search index and reviewed time assumptions (P4.4).
--
-- The plan names this step `0002_search`; version 0002 is already
-- `0002_file_times` from P3.1, so the next free number is 0003. The P5.1
-- analysis tables therefore take 0004.
--
-- Additive only. No existing row changes meaning, and the search index never
-- stores a copy of event text: it is an FTS5 external-content table that reads
-- from `events` at query time, so the index can be rebuilt from the facts and
-- can never quietly disagree with them.

-- Recorded investigator/parser time assumptions per parse run (plan Sections
-- 6, 9). Existing runs record the empty list, meaning "no assumption was
-- recorded", never a fabricated one.
ALTER TABLE parse_runs ADD COLUMN assumptions_json TEXT NOT NULL DEFAULT '[]';

-- unicode61 is the documented token semantics: word/phrase search, no
-- arbitrary substring matching, and no Unicode folding surprises.
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    summary,
    kind,
    host_claim,
    content = 'events',
    content_rowid = 'rowid',
    tokenize = 'unicode61'
);

-- Events are immutable facts: rows are never updated or deleted, and the
-- writer's `ON CONFLICT DO NOTHING` makes replays skip the insert (and so the
-- trigger) entirely. An AFTER INSERT trigger therefore keeps the index exactly
-- in step with the recorded events without any second write path.
CREATE TRIGGER IF NOT EXISTS events_fts_after_insert AFTER INSERT ON events
BEGIN
    INSERT INTO events_fts (rowid, summary, kind, host_claim)
    VALUES (new.rowid, new.summary, new.kind, new.host_claim);
END;

-- Existing cases already hold events recorded before this index existed. Build
-- the index from the facts rather than leaving those events unsearchable.
-- `rebuild` is idempotent: it clears the index and re-reads `events`.
INSERT INTO events_fts (events_fts) VALUES ('rebuild');

-- Time review reads every named time of a non-resolved event. The
-- UNIQUE(event_id, name) constraint already provides this access path; the
-- explicit index documents it as load-bearing for the review query.
CREATE INDEX IF NOT EXISTS event_times_by_event ON event_times(event_id, name);
