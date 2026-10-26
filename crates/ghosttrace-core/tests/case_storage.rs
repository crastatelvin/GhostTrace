//! P1.2 case-storage contract: exclusive creation, private directory
//! permissions, foreign-key rejection, unique locator/idempotency, newer
//! schema rejection, and interrupted transactions never exposing half a
//! batch. Uses real temporary case directories (plan Section 15).

use ghosttrace_core::domain::query::EventQuery;
use ghosttrace_core::error::CoreError;
use ghosttrace_core::service::{CaseSession, CreateCaseSpec};
use ghosttrace_core::storage::writer::{Param, WriteBatch, WriteOp};
use std::path::Path;

fn create_case(dir: &Path) -> CaseSession {
    CaseSession::create(
        dir,
        "investigation-1",
        CreateCaseSpec {
            label: "first look".into(),
            display_timezone: "UTC".into(),
            description: "synthetic".into(),
        },
    )
    .expect("case created")
}

fn acquisition_op(id: &str, case_id: &str) -> WriteOp {
    WriteOp::fact(
        "acquisitions",
        vec!["id", "case_id", "method", "claimed_source", "state"],
        vec![
            Param::Text(id.into()),
            Param::Text(case_id.into()),
            Param::Text("protected_copy".into()),
            Param::Text("src".into()),
            Param::Text("completed".into()),
        ],
    )
}

fn row_count(session: &CaseSession, sql: &str) -> i64 {
    let reader = session.reader().unwrap();
    reader
        .connection()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

#[test]
fn exclusive_creation_and_private_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    assert!(session.layout().database_path().exists());

    // Creating the same case again is refused, never silently overwritten.
    let again = CaseSession::create(
        dir.path(),
        "investigation-1",
        CreateCaseSpec {
            label: "second".into(),
            display_timezone: "UTC".into(),
            description: String::new(),
        },
    );
    assert!(matches!(again, Err(CoreError::InvalidInput(_))));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(session.layout().root())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "case directories must be owner-only");
        for sub in ["objects/sha256", "staging", "locks", "diagnostics"] {
            let mode = std::fs::metadata(session.layout().root().join(sub))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{sub} must be owner-only");
        }
    }

    // A missing case directory reports honestly rather than creating one.
    let missing = CaseSession::open(dir.path().join("nope.ghosttrace-case"));
    assert!(matches!(missing, Err(CoreError::InvalidInput(_))));
}

#[test]
fn foreign_key_rejection_leaves_no_rows() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    // An acquisition referencing a non-existent case must fail the batch.
    let dangling = WriteBatch::new().push(acquisition_op("acq-1", "missing-case"));
    assert!(session.writer().execute(dangling).is_err());
    assert_eq!(row_count(&session, "SELECT count(*) FROM acquisitions"), 0);
}

#[test]
fn unique_locator_enforcement_gives_idempotent_replays() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    let writer = session.writer();
    let observation = WriteOp::fact(
        "raw_observations",
        vec![
            "id",
            "parse_run_id",
            "acquisition_id",
            "evidence_id",
            "locator_kind",
            "locator_identity",
            "raw_fields_json",
        ],
        vec![
            Param::Text("obs-1".into()),
            Param::Text("run-1".into()),
            Param::Text("acq-1".into()),
            Param::Text("obj-1".into()),
            Param::Text("byte_range".into()),
            Param::Text("0:6:1".into()),
            Param::Text(r#"{"msg":"hello"}"#.into()),
        ],
    );
    // Parent rows must exist for the observation's foreign keys.
    let parents = WriteBatch::new()
        .push(WriteOp::fact(
            "cases",
            vec!["id", "label", "created_seconds"],
            vec![
                Param::Text("case-1".into()),
                Param::Text("l".into()),
                Param::Int(1_700_000_000),
            ],
        ))
        .push(acquisition_op("acq-1", "case-1"))
        .push(WriteOp::fact(
            "evidence_objects",
            vec![
                "id",
                "acquisition_id",
                "native_path_kind",
                "native_path_encoded",
                "kind",
                "byte_length",
                "digest_status",
                "sha256",
                "object_location",
            ],
            vec![
                Param::Text("obj-1".into()),
                Param::Text("acq-1".into()),
                Param::Text("unix".into()),
                Param::Text("logs%2Fapp.jsonl".into()),
                Param::Text("file_content".into()),
                Param::Int(12),
                Param::Text("complete".into()),
                Param::Bytes(vec![0xab; 32]),
                Param::OptText(Some("objects/sha256/ab".into())),
            ],
        ))
        .push(WriteOp::fact(
            "parse_runs",
            vec![
                "id",
                "acquisition_id",
                "parser_id",
                "parser_version",
                "state",
            ],
            vec![
                Param::Text("run-1".into()),
                Param::Text("acq-1".into()),
                Param::Text("jsonl".into()),
                Param::Text("1.0.0".into()),
                Param::Text("completed".into()),
            ],
        ));
    writer.execute(parents).unwrap();
    writer
        .execute(WriteBatch::new().push(observation.clone()))
        .unwrap();

    // Replaying the same locator identity inserts nothing.
    let replay = writer.execute(WriteBatch::new().push(observation)).unwrap();
    assert_eq!(
        replay.applied, 0,
        "same locator identity is an idempotent replay"
    );
    assert_eq!(
        row_count(&session, "SELECT count(*) FROM raw_observations"),
        1
    );
}

#[test]
fn reopened_case_keeps_raw_values_and_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let root = {
        let session = create_case(dir.path());
        session
            .writer()
            .execute(WriteBatch::new().push(WriteOp::fact(
                "cases",
                vec!["id", "label", "created_seconds"],
                vec![
                    Param::Text("case-1".into()),
                    Param::Text("persist".into()),
                    Param::Int(1_700_000_000),
                ],
            )))
            .unwrap();
        session.layout().root().to_path_buf()
    };

    let (session, report) = CaseSession::open(root).expect("reopen");
    assert!(report.migrations_applied.is_empty(), "nothing to migrate");
    let reader = session.reader().unwrap();
    let label: String = reader
        .connection()
        .query_row("SELECT label FROM cases WHERE id = 'case-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(label, "persist");
    let page = session
        .query_events(&EventQuery::with_revision("r1"))
        .unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(page.display_timezone, "UTC");
}

#[test]
fn newer_schema_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let database = create_case(dir.path())
        .layout()
        .database_path()
        .to_path_buf();
    {
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 7;")
            .unwrap();
    }
    let outcome = CaseSession::open(database.parent().unwrap().to_path_buf());
    assert!(matches!(outcome, Err(CoreError::SchemaIncompatible(_))));
}

#[test]
fn interrupted_transaction_does_not_expose_half_a_batch() {
    let dir = tempfile::tempdir().unwrap();
    let session = create_case(dir.path());
    // The third op violates the acquisition foreign key; the first two ops
    // must vanish with it.
    let batch = WriteBatch::new()
        .push(WriteOp::fact(
            "cases",
            vec!["id", "label", "schema_version", "created_seconds"],
            vec![
                Param::Text("case-x".into()),
                Param::Text("l".into()),
                Param::Int(1),
                Param::Int(1_700_000_000),
            ],
        ))
        .push(acquisition_op("acq-1", "case-x"))
        .push(acquisition_op("acq-2", "missing-case"));
    assert!(session.writer().execute(batch).is_err());
    assert_eq!(
        row_count(
            &session,
            "SELECT count(*) FROM acquisitions WHERE id = 'acq-1'"
        ),
        0,
        "the first insert must not survive the failed batch"
    );
    assert_eq!(
        row_count(&session, "SELECT count(*) FROM cases WHERE id = 'case-x'"),
        0,
        "nor may any earlier op of the same batch"
    );
}
