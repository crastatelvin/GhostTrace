//! P4.3 package consistency: a main database plus its committed WAL, and the
//! sidecar combinations that must not silently look complete.

mod support;

use support::Harness;

const CHROMIUM_VISITS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/browser/chromium-visits.sql"
));

const VISIT_ROWS: &[&str] = &[
    "INSERT INTO urls VALUES (1,'https://wal.test/committed','Committed in WAL',1,13437532800000000,0)",
    "INSERT INTO visits VALUES (1,1,13437532800000000,0,1,0,'',0)",
];

#[test]
fn a_committed_wal_row_is_imported_but_a_missing_wal_is_partial() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let files = support::wal_database(dir.path(), CHROMIUM_VISITS, VISIT_ROWS);
    assert!(
        !files.wal.is_empty(),
        "the fixture must exercise WAL frames"
    );

    let main_only = harness.capture(&[("History", &files.main)]);
    let without_wal = harness
        .import(&main_only, "History", |_| {})
        .expect("main-only import");
    assert_eq!(without_wal.state, "partial");
    assert_eq!(without_wal.events, 0, "committed rows are only in the WAL");
    assert!(
        without_wal
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "wal_missing"),
        "{:?}",
        without_wal.diagnostics
    );

    let mut package_files: Vec<(&str, &[u8])> = vec![
        ("History", files.main.as_slice()),
        ("History-wal", files.wal.as_slice()),
    ];
    if let Some(shm) = files.shm.as_deref() {
        package_files.push(("History-shm", shm));
    }
    let package = harness.capture(&package_files);
    let with_wal = harness
        .import(&package, "History", |_| {})
        .expect("package import");
    assert_eq!(with_wal.state, "completed");
    assert_eq!(with_wal.events, 1);
    assert_eq!(with_wal.observations, 1);
    assert_eq!(
        harness
            .scalar(
                "SELECT chosen_seconds FROM events WHERE parse_run_id = ?1",
                &[&with_wal.run_id],
            )
            .as_deref(),
        Some("1793059200")
    );
    assert_eq!(
        harness
            .scalar(
                "SELECT raw_fields_json FROM raw_observations WHERE parse_run_id = ?1",
                &[&with_wal.run_id],
            )
            .map(|raw| raw.contains("https://wal.test/committed")),
        Some(true)
    );
}

#[test]
fn inconsistent_sidecars_are_rejected_instead_of_guessed() {
    let mut harness = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let files = support::wal_database(dir.path(), CHROMIUM_VISITS, VISIT_ROWS);
    let bogus = b"this is not a sqlite write-ahead log header".to_vec();
    let ephemeral = b"not a shared-memory index".to_vec();
    let rollback = b"not a rollback journal either".to_vec();

    let bad_wal = harness.capture(&[("History", &files.main), ("History-wal", &bogus)]);
    let error = harness
        .import(&bad_wal, "History", |_| {})
        .expect_err("invalid WAL header");
    assert_eq!(error.code(), "unsupported_format");
    assert!(error.detail().contains("WAL"), "{error}");

    let orphan_shm = harness.capture(&[("History", &files.main), ("History-shm", &ephemeral)]);
    let error = harness
        .import(&orphan_shm, "History", |_| {})
        .expect_err("shm without wal");
    assert_eq!(error.code(), "unsupported_format");
    assert!(error.detail().contains("-shm"), "{error}");

    let journal = harness.capture(&[("History", &files.main), ("History-journal", &rollback)]);
    let error = harness
        .import(&journal, "History", |_| {})
        .expect_err("rollback journal");
    assert_eq!(error.code(), "unsupported_format");
    assert!(error.detail().contains("rollback-journal"), "{error}");
}

#[test]
fn a_main_database_without_a_valid_header_is_rejected() {
    let mut harness = Harness::new();
    let acquisition = harness.capture(&[("History", b"not a database at all")]);
    let error = harness
        .import(&acquisition, "History", |_| {})
        .expect_err("invalid database");
    assert_eq!(error.code(), "unsupported_format");
}
