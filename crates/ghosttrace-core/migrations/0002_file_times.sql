-- 0002_file_times: record the source observation times a snapshot diff needs.
--
-- Additive only. Existing rows keep NULL, meaning "not recorded", never a
-- fabricated instant. Both halves are required together: seconds without
-- nanos would silently lose sub-second precision.

ALTER TABLE file_observations ADD COLUMN source_mtime_seconds INTEGER;
ALTER TABLE file_observations ADD COLUMN source_mtime_nanos INTEGER;
