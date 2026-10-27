//! P4.3 schema safety: hostile schema objects, contract mismatches, corrupt
//! pages, SQL limits, and query deadlines are rejected, never half-parsed.

mod support;

use support::Harness;

const CHROMIUM_VISITS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/chromium-visits.sql"
));

fn import_bytes(harness: &mut Harness, bytes: &[u8]) -> ghosttrace_core::error::CoreError {
    let acquisition = harness.capture(&[("History", bytes)]);
    harness
        .import(&acquisition, "History", |_| {})
        .expect_err("package must be rejected")
}

#[test]
fn views_are_rejected_without_executing_them() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let schema =
        format!("{CHROMIUM_VISITS}\nCREATE VIEW suspect AS SELECT load_extension('/tmp/evil.so');");
    let bytes = support::sqlite_bytes(dir.path(), "History", &schema, &[]);
    let error = import_bytes(&mut harness, &bytes);
    assert_eq!(error.code(), "unsupported_format");
    assert!(error.detail().contains("view"), "{error}");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM parse_runs WHERE parser_id LIKE 'browser.%'",
            &[]
        ),
        0,
        "a rejected package never creates a run"
    );
}

#[test]
fn virtual_tables_are_rejected() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let schema = format!("{CHROMIUM_VISITS}\nCREATE VIRTUAL TABLE suspect USING fts5(content);");
    let bytes = support::sqlite_bytes(dir.path(), "History", &schema, &[]);
    let error = import_bytes(&mut harness, &bytes);
    assert_eq!(error.code(), "unsupported_format");
    assert!(error.detail().contains("virtual table"), "{error}");
}

#[test]
fn a_missing_contract_column_is_named() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let schema = "
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
                           visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                             from_visit INTEGER);
    ";
    let bytes = support::sqlite_bytes(dir.path(), "History", schema, &[]);
    let error = import_bytes(&mut harness, &bytes);
    assert_eq!(error.code(), "unsupported_format");
    assert!(error.detail().contains("visits"), "{error}");
    assert!(error.detail().contains("transition"), "{error}");
}

#[test]
fn a_corrupt_page_is_reported_as_corrupt_evidence() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let mut rows = Vec::new();
    for index in 1..=200 {
        rows.push(format!(
            "INSERT INTO urls VALUES ({index},'https://corrupt.test/{index}/{}','Title {index}',1,13437532800000000,0)",
            "x".repeat(64)
        ));
        rows.push(format!(
            "INSERT INTO visits VALUES ({index},{index},13437532800000000,0,1,0,'',0)"
        ));
    }
    let refs: Vec<&str> = rows.iter().map(String::as_str).collect();
    let mut bytes = support::sqlite_bytes(dir.path(), "History", CHROMIUM_VISITS, &refs);
    assert!(bytes.len() > 4200, "fixture must span more than one page");
    // Corrupt the cell-count area of the first b-tree data page.
    bytes[4096 + 3] ^= 0xff;
    let error = import_bytes(&mut harness, &bytes);
    assert_eq!(error.code(), "corrupt_evidence");
    assert_eq!(
        harness.count(
            "SELECT count(*) FROM parse_runs WHERE parser_id LIKE 'browser.%'",
            &[]
        ),
        0,
        "corruption is detected before a run row is written"
    );
}
