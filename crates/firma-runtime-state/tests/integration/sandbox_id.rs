use std::assert_matches;
use std::str::FromStr as _;

use firma_runtime_state::{SandboxId, SandboxIdParseError};

const UUID_V7: &str = "01900000-0000-7000-8000-000000000001";

#[test]
fn generated_id_is_uuid_v7() {
    let generated = SandboxId::generate();
    assert!(generated.to_string().parse::<SandboxId>().is_ok());
}

#[test]
fn display_is_canonical() {
    let id = SandboxId::from_str(UUID_V7).expect("valid UUID v7 fixture");
    assert_eq!(id.to_string(), UUID_V7);
}

#[test]
fn serde_round_trip_uses_a_string() {
    let id = SandboxId::from_str(UUID_V7).expect("valid UUID v7 fixture");
    let encoded = serde_json::to_string(&id).expect("serialize sandbox id");
    assert_eq!(encoded, format!("\"{UUID_V7}\""));
    assert_eq!(
        serde_json::from_str::<SandboxId>(&encoded).expect("deserialize sandbox id"),
        id
    );
}

#[test]
fn malformed_uuid_is_rejected() {
    let error = "../outside"
        .parse::<SandboxId>()
        .expect_err("malformed UUID must be rejected");

    assert_matches!(&error, SandboxIdParseError::Malformed(_));
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be a UUID v7: invalid character: found `.` at 0");
}

#[test]
fn non_v7_uuid_is_rejected() {
    let error = "550e8400-e29b-41d4-a716-446655440000"
        .parse::<SandboxId>()
        .expect_err("non-v7 UUID must be rejected");

    assert_matches!(&error, SandboxIdParseError::NotVersion7);
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be a UUID v7");
}

#[test]
fn non_rfc_9562_variant_is_rejected() {
    let error = "01900000-0000-7000-0000-000000000001"
        .parse::<SandboxId>()
        .expect_err("non-RFC 9562 UUID variant must be rejected");

    assert_matches!(&error, SandboxIdParseError::NotRfc9562);
    insta::assert_snapshot!(error.to_string(), @"sandbox id must use the RFC 9562 UUID variant");
}

#[test]
fn deserialization_rejects_non_v7_uuid() {
    let encoded = "\"550e8400-e29b-41d4-a716-446655440000\"";
    let error = serde_json::from_str::<SandboxId>(encoded)
        .expect_err("deserialization must reject non-v7 UUIDs");

    assert_matches!(error.classify(), serde_json::error::Category::Data);
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be a UUID v7");
}
