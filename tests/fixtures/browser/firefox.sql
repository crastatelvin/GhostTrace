CREATE TABLE moz_places (
  id INTEGER PRIMARY KEY,
  url LONGVARCHAR,
  title LONGVARCHAR,
  rev_host LONGVARCHAR,
  visit_count INTEGER DEFAULT 0,
  hidden INTEGER DEFAULT 0 NOT NULL,
  typed INTEGER DEFAULT 0 NOT NULL,
  frecency INTEGER DEFAULT -1 NOT NULL,
  last_visit_date INTEGER,
  guid TEXT,
  foreign_count INTEGER DEFAULT 0 NOT NULL,
  url_hash INTEGER DEFAULT 0 NOT NULL,
  description TEXT,
  preview_image_url TEXT,
  site_name TEXT,
  origin_id INTEGER,
  recalc_frecency INTEGER DEFAULT 0 NOT NULL,
  alt_frecency INTEGER,
  recalc_alt_frecency INTEGER DEFAULT 0 NOT NULL
);

CREATE TABLE moz_historyvisits (
  id INTEGER PRIMARY KEY,
  from_visit INTEGER,
  place_id INTEGER,
  visit_date INTEGER,
  visit_type INTEGER,
  session INTEGER,
  source INTEGER
);
