//! P0.1 storage-stack verification (plan Sections 3, 8, 17/P0.1).
//!
//! Records what the linked SQLite runtime actually is, instead of trusting the
//! crate version: library version, compile options, FTS5 availability, foreign
//! key enforcement, defensive-schema pragma support, and WAL behavior.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes concurrent WAL probe files within one process.
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize)]
pub struct Fts5Check {
    pub created_and_indexed: bool,
    pub phrase_match_found: bool,
}

#[derive(Debug, Serialize)]
pub struct SqliteReport {
    pub rusqlite_crate_version: String,
    pub sqlite_library_version: String,
    pub compile_options: Vec<String>,
    pub fts5: Fts5Check,
    pub foreign_keys_enforced: bool,
    pub trusted_schema_off_supported: bool,
    pub wal_mode_supported: bool,
}

fn in_memory() -> rusqlite::Connection {
    rusqlite::Connection::open_in_memory().expect("in-memory sqlite")
}

fn check_fts5(conn: &rusqlite::Connection) -> Fts5Check {
    let created = conn
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS pilot_fts USING fts5(body);
             INSERT INTO pilot_fts(body) VALUES ('alpha beta');
             INSERT INTO pilot_fts(body) VALUES ('gamma delta');",
        )
        .is_ok();
    let matched = conn
        .query_row(
            "SELECT count(*) FROM pilot_fts WHERE pilot_fts MATCH 'alpha'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    Fts5Check {
        created_and_indexed: created,
        phrase_match_found: matched,
    }
}

fn check_foreign_keys(conn: &rusqlite::Connection) -> bool {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE parent (id INTEGER PRIMARY KEY);
         CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id));
         INSERT INTO child (id, parent_id) VALUES (1, 999);",
    )
    .is_err()
}

/// Produce the P0.1 runtime report for the linked SQLite build.
pub fn sqlite_report() -> SqliteReport {
    let conn = in_memory();

    let sqlite_library_version: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .expect("sqlite_version()");

    let compile_options: Vec<String> = {
        let mut stmt = conn
            .prepare("PRAGMA compile_options")
            .expect("compile_options");
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .expect("compile_options rows");
        rows.map(|r| r.expect("compile_options row")).collect()
    };

    let fts5 = check_fts5(&conn);

    let foreign_keys_enforced = check_foreign_keys(&conn);

    let trusted_schema_off_supported = conn.execute_batch("PRAGMA trusted_schema = OFF;").is_ok();

    let wal_mode_supported = {
        // WAL needs a real file; use a private temp database.
        let probe = PROBE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "ghosttrace-p0-wal-{}-{probe}.db",
            std::process::id()
        ));
        let result = (|| -> rusqlite::Result<bool> {
            let file_conn = rusqlite::Connection::open(&path)?;
            let mode: String =
                file_conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
            file_conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")?;
            let n: i64 = file_conn.query_row("SELECT count(*) FROM t", [], |r| r.get(0))?;
            Ok(mode.eq_ignore_ascii_case("wal") && n == 1)
        })();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        result.unwrap_or(false)
    };

    SqliteReport {
        rusqlite_crate_version: rusqlite::version().to_string(),
        sqlite_library_version,
        compile_options,
        fts5,
        foreign_keys_enforced,
        trusted_schema_off_supported,
        wal_mode_supported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fts5_phrase_search_works() {
        let report = sqlite_report();
        assert!(
            report.fts5.created_and_indexed,
            "FTS5 virtual table must be creatable in the bundled runtime"
        );
        assert!(report.fts5.phrase_match_found, "FTS5 MATCH must find rows");
    }

    #[test]
    fn foreign_keys_are_enforced() {
        assert!(sqlite_report().foreign_keys_enforced);
    }

    #[test]
    fn defensive_schema_pragma_is_accepted() {
        assert!(sqlite_report().trusted_schema_off_supported);
    }

    #[test]
    fn wal_mode_works() {
        assert!(sqlite_report().wal_mode_supported);
    }

    #[test]
    fn library_version_is_reported() {
        let report = sqlite_report();
        assert!(!report.sqlite_library_version.is_empty());
        eprintln!("sqlite library version: {}", report.sqlite_library_version);
        eprintln!("compile options: {:#?}", report.compile_options);
    }
}
