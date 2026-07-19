use std::assert_matches;
use std::str::FromStr as _;

use firma_runtime_state::{SandboxId, SandboxIdParseError};

const SANDBOX_ID: &str = "sbx_01j0000000e008000000000001";

#[test]
fn generated_id_is_sbx_typeid() {
    let generated = SandboxId::generate();
    assert!(generated.to_string().starts_with("sbx_"));
    assert!(generated.to_string().parse::<SandboxId>().is_ok());
}

#[test]
fn display_is_canonical() {
    let id = SandboxId::from_str(SANDBOX_ID).expect("valid sandbox ID fixture");
    assert_eq!(id.to_string(), SANDBOX_ID);
}

#[test]
fn serde_round_trip_uses_a_string() {
    let id = SandboxId::from_str(SANDBOX_ID).expect("valid sandbox ID fixture");
    let encoded = serde_json::to_string(&id).expect("serialize sandbox id");
    assert_eq!(encoded, format!("\"{SANDBOX_ID}\""));
    assert_eq!(
        serde_json::from_str::<SandboxId>(&encoded).expect("deserialize sandbox id"),
        id
    );
}

#[test]
fn malformed_typeid_is_rejected() {
    let error = "sbx_invalid"
        .parse::<SandboxId>()
        .expect_err("malformed TypeID must be rejected");

    assert_matches!(&error, SandboxIdParseError::InvalidSuffix(_));
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be a valid TypeID: sbx_invalid has an invalid suffix");
}

#[test]
fn raw_uuid_is_rejected() {
    let error = "01900000-0000-7000-8000-000000000001"
        .parse::<SandboxId>()
        .expect_err("raw UUID must be rejected");

    assert_matches!(&error, SandboxIdParseError::IncorrectPrefix(_));
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be a TypeID with `sbx` as prefix: 01900000-0000-7000-8000-000000000001 does not start with the expected prefix");
}

#[test]
fn non_v7_typeid_is_rejected() {
    let error = "sbx_2n1t201rmv88eb2sj4cn248g00"
        .parse::<SandboxId>()
        .expect_err("non-v7 TypeID must be rejected");

    assert_matches!(&error, SandboxIdParseError::NotVersion7 { actual: 4, .. });
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be backed by a UUID v7: sbx_2n1t201rmv88eb2sj4cn248g00 is backed by a UUID v4");
}

#[test]
fn non_rfc_9562_variant_is_rejected() {
    let error = "sbx_01j0000000e000000000000001"
        .parse::<SandboxId>()
        .expect_err("non-RFC 9562 TypeID variant must be rejected");

    assert_matches!(
        &error,
        SandboxIdParseError::NotRfc9562 {
            actual: uuid::Variant::NCS,
            ..
        }
    );
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be backed by an RFC 9562 UUID: sbx_01j0000000e000000000000001 is backed by a UUID with the NCS variant");
}

#[test]
fn deserialization_rejects_non_v7_typeid() {
    let encoded = "\"sbx_2n1t201rmv88eb2sj4cn248g00\"";
    let error = serde_json::from_str::<SandboxId>(encoded)
        .expect_err("deserialization must reject non-v7 UUIDs");

    assert_matches!(error.classify(), serde_json::error::Category::Data);
    insta::assert_snapshot!(error.to_string(), @"sandbox id must be backed by a UUID v7: sbx_2n1t201rmv88eb2sj4cn248g00 is backed by a UUID v4");
}
