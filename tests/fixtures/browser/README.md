# Browser history fixture definitions (P4.3)

The adapter tests do not commit binary databases. They build SQLite files from
the schema definitions below at test time, so the fixture is reviewable and the
bytes are reproducible. The definitions are synthetic; no captured personal
history is tracked here.

| Fixture | Schema | Schema fingerprint |
| --- | --- | --- |
| `chromium-visits.sql` | Chromium `urls` + `visits` | `f2d4b0781f8d12de18205bc636eb6b76f3152b7ba36d8d258d47156754deae16` |
| `chromium-downloads.sql` | Chromium `urls` + `visits` + `downloads` + `downloads_url_chains` | `ff301a6f72e24e351de3192155ecd344a9673d003d24c64fcefd7ba2370b493c` |
| `chromium-downloads-partial.sql` | Chromium contract with a reduced `downloads` table | not used for a fingerprint; proves unavailable fields are reported |
| `firefox.sql` | Firefox `moz_places` + `moz_historyvisits` | `a40374e3ec8fe005161985a5738750be3a9c415048637e482b101886f2ed1e11` |

A fingerprint is SHA-256 over the adapter id followed by, for each queried
table that exists, the table name and every column's name, declared type,
`NOT NULL` flag, and primary-key flag. It is recorded in the parse run's
configuration digest. Adding unrelated or optional columns changes the
fingerprint but does not by itself make a package unsupported; the required
contract columns are checked by name. Removing a required column is rejected
with `unsupported_format` and names the missing contract column.

**Validated scope.** These definitions were validated, not an installation of
a particular browser release. A real Chromium or Firefox profile with a
superset of the required columns is expected to parse, and its actual
fingerprint is recorded in the run configuration; that expectation has not yet
been confirmed against a real browser installation. No version range is
claimed.

Expected mappings exercised by the tests:

- `chromium-visits.sql`: Chromium microseconds since 1601-01-01, referrer URL
  via `from_visit`, transition integer preserved verbatim, sync labels from
  `originator_cache_guid` / `is_known_to_sync`, logical row locators.
- `chromium-downloads.sql`: raw `current_path`/`target_path`, start/end Chrome
  times, `opened`, state, MIME type, and the ordered `downloads_url_chains`
  URL chain.
- `chromium-downloads-partial.sql`: absent known download columns and the
  absent URL-chain table are reported by `download_fields_unavailable`; no raw
  field is fabricated.
- `firefox.sql`: PRTime microseconds since the Unix epoch, referrer URL,
  `source` mapped to local/synced/unknown.
