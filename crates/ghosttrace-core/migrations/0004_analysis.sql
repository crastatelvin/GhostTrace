-- 0004_analysis: scoped entities and explainable relationships (P5.1).
--
-- The plan names this step `0003_analysis`; version 0003 is `0003_search`
-- (P4.4), so the next free number is 0004. Additive only: no existing row
-- changes meaning and no column is rewritten.

-- Analysis needs to know which evidence object (and where inside it) each
-- normalized event came from, so entity evidence can be re-read instead of
-- guessing from the summary. Events recorded before this migration keep NULL:
-- the link was never stored and inferring it would be an invention.
ALTER TABLE events ADD COLUMN evidence_id TEXT;
ALTER TABLE events ADD COLUMN locator_identity TEXT;
CREATE INDEX IF NOT EXISTS events_by_source ON events(evidence_id, locator_identity);

-- Entity neighbourhoods are read entity -> events ("what touched this IP?").
-- The primary key already covers event -> entities.
CREATE INDEX IF NOT EXISTS event_entities_by_entity
    ON event_entities(entity_id, event_id, role);

-- One edge per rule version for one ordered entity pair. Correlation replays
-- facts instead of multiplying duplicates, and canonical endpoint order means
-- A->B and B->A cannot both exist. Existing cases hold no relationship rows
-- (nothing wrote them before P5.1), so this cannot fail on old data.
CREATE UNIQUE INDEX IF NOT EXISTS relationships_pair
    ON relationships(kind, source_entity_id, target_entity_id, rule_id, rule_version);

-- Relationship queries are bounded keyset reads filtered by endpoint or rule.
CREATE INDEX IF NOT EXISTS relationships_target ON relationships(target_entity_id, id);
CREATE INDEX IF NOT EXISTS relationships_by_rule
    ON relationships(rule_id, rule_version, id);
