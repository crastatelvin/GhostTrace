//! P8.2 worker protocol contract: frame bounds, message validation, and the
//! worker's refusal paths.
//!
//! The parent treats worker output as untrusted, so every bound here is a
//! refusal, not a clamp: a malformed frame or record fails the job instead of
//! being partially accepted.

use std::io::Cursor;

use ghosttrace_core::worker::protocol::{
    MAX_BATCH_FRAME, MAX_CONTROL_FRAME, PROTOCOL_VERSION, read_frame, serve, validate_wire_record,
    write_frame,
};
use serde_json::Value;

fn frame(body: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_frame(&mut out, body.as_bytes(), MAX_CONTROL_FRAME).expect("frame");
    out
}

fn hello(protocol: u32, version: &str) -> Vec<u8> {
    frame(&format!(
        r#"{{"type":"hello","protocol":{protocol},"version":"{version}"}}"#
    ))
}

fn parse(path: &str) -> Vec<u8> {
    frame(&format!(
        r#"{{"type":"parse","job_id":"job-1","format":"evtx","path":"{path}","max_records":10,"max_record_bytes":1024}}"#
    ))
}

fn responses(bytes: &[u8]) -> Vec<Value> {
    let mut input = Cursor::new(bytes.to_vec());
    let mut out = Vec::new();
    while let Some(body) = read_frame(&mut input, MAX_BATCH_FRAME).expect("frame") {
        out.push(serde_json::from_slice(&body).expect("json"));
    }
    out
}

fn valid_record() -> Value {
    serde_json::json!({
        "locator": "evtx-record:42",
        "locator_kind": "binary_record",
        "raw_json": "{\"Event\":{}}",
        "mapped_json": null,
        "event": {
            "kind": "windows.event_log",
            "summary": "an event",
            "host": "host",
            "times": [{
                "name": "logged",
                "semantic": "LoggedTime",
                "value": {
                    "status": "Resolved",
                    "candidates": [{"seconds": 1, "nanos": 0}],
                    "raw": {
                        "field": "SystemTime",
                        "integer": "133700123456789012",
                        "text": null,
                        "epoch": "Unix",
                        "unit": "Seconds",
                        "declared_precision": "Seconds"
                    },
                    "semantic": "LoggedTime",
                    "clock_domain": "Host",
                    "declared_precision": "Seconds",
                    "assumptions": []
                }
            }]
        },
        "diagnostics": []
    })
}

fn validate(record: &Value, max_record_bytes: usize) -> Result<(), String> {
    validate_wire_record(record.to_string().as_bytes(), max_record_bytes)
}

#[test]
fn frames_round_trip_and_end_at_a_boundary() {
    let body = br#"{"type":"done"}"#;
    let mut out = Vec::new();
    write_frame(&mut out, body, MAX_CONTROL_FRAME).expect("write");
    let mut input = Cursor::new(out.clone());
    let read = read_frame(&mut input, MAX_CONTROL_FRAME)
        .expect("read")
        .expect("one frame");
    assert_eq!(read, body);
    assert_eq!(
        read_frame(&mut input, MAX_CONTROL_FRAME).expect("eof"),
        None
    );
}

#[test]
fn a_frame_over_the_bound_is_refused_without_writing() {
    let body = vec![b'x'; MAX_CONTROL_FRAME + 1];
    let mut out = Vec::new();
    let error = write_frame(&mut out, &body, MAX_CONTROL_FRAME).expect_err("over the bound");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(out.is_empty(), "a refused frame writes nothing");
}

#[test]
fn an_oversize_length_prefix_is_refused() {
    let mut input = Cursor::new(((MAX_BATCH_FRAME + 1) as u32).to_be_bytes().to_vec());
    let error = read_frame(&mut input, MAX_BATCH_FRAME).expect_err("over the bound");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn a_zero_length_frame_is_refused() {
    let mut input = Cursor::new(vec![0_u8; 4]);
    let error = read_frame(&mut input, MAX_CONTROL_FRAME).expect_err("zero length");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn a_truncated_body_is_an_error_not_a_shorter_message() {
    let mut input = Cursor::new(vec![0, 0, 0, 10, b'{', b'}']);
    assert!(read_frame(&mut input, MAX_CONTROL_FRAME).is_err());
}

#[test]
fn an_unknown_message_type_is_not_a_message() {
    assert!(
        serde_json::from_str::<ghosttrace_core::worker::protocol::Response>(r#"{"type":"evil"}"#)
            .is_err()
    );
}

#[test]
fn a_well_formed_record_passes_validation() {
    validate(&valid_record(), 1 << 20).expect("valid");
}

#[test]
fn malformed_records_are_refused() {
    let mut bad_kind = valid_record();
    bad_kind["locator_kind"] = "sql_row".into();
    let mut control_locator = valid_record();
    control_locator["locator"] = "evtx-record:1\u{1b}".into();
    let mut raw_not_json = valid_record();
    raw_not_json["raw_json"] = "not json".into();
    let mut raw_scalar = valid_record();
    raw_scalar["raw_json"] = "42".into();
    let mut mapped_array = valid_record();
    mapped_array["mapped_json"] = "[]".into();
    let mut upper_kind = valid_record();
    upper_kind["event"]["kind"] = "Windows.Event".into();
    let mut empty_kind = valid_record();
    empty_kind["event"]["kind"] = "".into();
    let mut too_many_times = valid_record();
    let time = valid_record()["event"]["times"][0].clone();
    too_many_times["event"]["times"] = Value::Array(vec![time; 9]);
    let mut too_many_candidates = valid_record();
    too_many_candidates["event"]["times"][0]["value"]["candidates"] =
        Value::Array(vec![serde_json::json!({"seconds": 1, "nanos": 0}); 9]);
    let mut bad_integer = valid_record();
    bad_integer["event"]["times"][0]["value"]["raw"]["integer"] = "not-a-number".into();
    let mut nothing = valid_record();
    nothing["raw_json"] = Value::Null;
    nothing["event"] = Value::Null;
    let mut unknown_field = valid_record();
    unknown_field["surprise"] = true.into();

    let cases = [
        (bad_kind, "locator kind"),
        (control_locator, "control character"),
        (raw_not_json, "not valid JSON"),
        (raw_scalar, "object or array"),
        (mapped_array, "not a JSON object"),
        (upper_kind, "machine code"),
        (empty_kind, "event kind has 0 bytes"),
        (too_many_times, "named times"),
        (too_many_candidates, "time candidates"),
        (bad_integer, "not an i128"),
        (nothing, "no observation"),
        (unknown_field, "unknown field"),
    ];
    for (record, expected) in cases {
        let error = validate(&record, 1 << 20).expect_err(expected);
        assert!(
            error.contains(expected),
            "expected {expected:?} in {error:?}"
        );
    }
    let error = validate(&valid_record(), 8).expect_err("raw over the limit");
    assert!(error.contains("over the 8 byte limit"), "{error}");
}

#[test]
fn a_journal_array_raw_record_is_accepted() {
    let mut record = valid_record();
    record["raw_json"] = r#"[["MESSAGE","hello"],["_BOOT_ID","abc"]]"#.into();
    record["event"] = Value::Null;
    validate(&record, 1 << 20).expect("journal raw records are ordered pairs");
}

#[test]
fn the_worker_refuses_a_foreign_protocol() {
    let mut input = Cursor::new(hello(PROTOCOL_VERSION + 1, "0.0.0"));
    let mut output = Vec::new();
    assert_eq!(serve(&mut input, &mut output), 2);
    let responses = responses(&output);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["type"], "failed");
    assert_eq!(responses[0]["code"], "incompatible_worker");
}

#[test]
fn the_worker_refuses_a_missing_handshake() {
    let mut input = Cursor::new(Vec::new());
    let mut output = Vec::new();
    assert_eq!(serve(&mut input, &mut output), 2);
    assert!(output.is_empty());
}

#[test]
fn the_worker_refuses_a_path_outside_its_private_directory() {
    let mut bytes = hello(PROTOCOL_VERSION, env!("CARGO_PKG_VERSION"));
    bytes.extend(parse("/etc/passwd"));
    let mut input = Cursor::new(bytes);
    let mut output = Vec::new();
    assert_eq!(serve(&mut input, &mut output), 1);
    let responses = responses(&output);
    assert_eq!(responses[0]["type"], "ready");
    assert_eq!(responses[1]["type"], "failed");
    assert_eq!(responses[1]["code"], "invalid_input");
    assert!(
        responses[1]["message"]
            .as_str()
            .unwrap()
            .contains("outside the worker's private directory"),
        "{}",
        responses[1]
    );
}
