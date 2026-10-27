CREATE TABLE urls (
  id INTEGER PRIMARY KEY,
  url LONGVARCHAR,
  title LONGVARCHAR,
  visit_count INTEGER DEFAULT 0,
  last_visit_time INTEGER NOT NULL,
  hidden INTEGER DEFAULT 0
);

CREATE TABLE visits (
  id INTEGER PRIMARY KEY,
  url INTEGER NOT NULL,
  visit_time INTEGER NOT NULL,
  from_visit INTEGER,
  transition INTEGER DEFAULT 0,
  visit_duration INTEGER DEFAULT 0,
  originator_cache_guid TEXT,
  is_known_to_sync BOOLEAN DEFAULT FALSE
);
