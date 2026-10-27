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

CREATE TABLE downloads (
  id INTEGER PRIMARY KEY,
  guid TEXT,
  current_path TEXT,
  target_path TEXT,
  start_time INTEGER,
  received_bytes INTEGER,
  total_bytes INTEGER,
  state INTEGER,
  danger_type INTEGER,
  interrupt_reason INTEGER,
  hash BLOB,
  end_time INTEGER,
  opened INTEGER,
  last_access_time INTEGER,
  transient INTEGER,
  referrer TEXT,
  site_url TEXT,
  tab_url TEXT,
  tab_referrer_url TEXT,
  http_method TEXT,
  by_ext_id TEXT,
  by_ext_name TEXT,
  etag TEXT,
  last_modified TEXT,
  mime_type TEXT,
  original_mime_type TEXT
);

CREATE TABLE downloads_url_chains (
  id INTEGER NOT NULL,
  chain_index INTEGER NOT NULL,
  url LONGVARCHAR NOT NULL,
  PRIMARY KEY (id, chain_index)
);
