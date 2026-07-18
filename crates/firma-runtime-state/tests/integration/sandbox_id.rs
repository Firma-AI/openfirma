use std::str::FromStr as _;

use firma_runtime_state::{SandboxId, SandboxIdParseError};

const UUID_V7: &str = "01900000-0000-7000-8000-000000000001";

#[test]
fn generated_id_is_uuid_v7() {
    let generated = SandboxId::generate();
    assert!(generated.to_string().parse::<SandboxId>().is_ok());
}

#[test]
fn display_and_compact_are_canonical() {
    let id = SandboxId::from_str(UUID_V7).expect("valid UUID v7 fixture");
    assert_eq!(id.to_string(), UUID_V7);
    assert_eq!(id.compact(), "01900000");
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
    assert!(matches!(
        "../outside".parse::<SandboxId>(),
        Err(SandboxIdParseError::Malformed(_))
    ));
}

#[test]
fn non_v7_uuid_is_rejected() {
    assert!(matches!(
        "550e8400-e29b-41d4-a716-446655440000".parse::<SandboxId>(),
        Err(SandboxIdParseError::NotVersion7)
    ));
}

#[test]
fn non_rfc_9562_variant_is_rejected() {
    assert!(matches!(
        "01900000-0000-7000-0000-000000000001".parse::<SandboxId>(),
        Err(SandboxIdParseError::NotRfc9562)
    ));
}

#[test]
fn deserialization_rejects_non_v7_uuid() {
    let encoded = "\"550e8400-e29b-41d4-a716-446655440000\"";
    assert!(serde_json::from_str::<SandboxId>(encoded).is_err());
}
