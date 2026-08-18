use std::assert_matches;

use firma_identifiers::{AgentId, ApprovalTokenId, AuditEventId, SandboxId, SessionId, TokenId};

#[test]
fn generated_type_ids_have_their_canonical_prefixes_and_round_trip() {
    let ids = [
        AgentId::generate().to_string(),
        SandboxId::generate().to_string(),
        TokenId::generate().to_string(),
        AuditEventId::generate().to_string(),
        ApprovalTokenId::generate().to_string(),
    ];

    assert!(ids[0].starts_with("agt_"));
    assert!(ids[0].parse::<AgentId>().is_ok());
    assert!(ids[1].starts_with("sbx_"));
    assert!(ids[1].parse::<SandboxId>().is_ok());
    assert!(ids[2].starts_with("ctok_"));
    assert!(ids[2].parse::<TokenId>().is_ok());
    assert!(ids[3].starts_with("aevt_"));
    assert!(ids[3].parse::<AuditEventId>().is_ok());
    assert!(ids[4].starts_with("atok_"));
    assert!(ids[4].parse::<ApprovalTokenId>().is_ok());
}

#[test]
fn type_ids_serialize_as_strings() {
    let id: AgentId = "agt_01j0000000e008000000000001"
        .parse()
        .expect("valid agent ID fixture");
    let encoded = serde_json::to_string(&id).expect("serialize agent ID");

    assert_eq!(encoded, r#""agt_01j0000000e008000000000001""#);
    assert_eq!(
        serde_json::from_str::<AgentId>(&encoded).expect("deserialize agent ID"),
        id
    );
}

#[test]
fn type_id_rejects_incorrect_prefix() {
    let error = "sbx_01j0000000e008000000000001"
        .parse::<AgentId>()
        .expect_err("sandbox TypeID must not parse as an agent ID");

    insta::assert_snapshot!(error.to_string(), @"agent id must start with `agt` as prefix: `sbx_01j0000000e008000000000001` does not");
}

#[test]
fn type_id_rejects_malformed_suffix() {
    let error = "ctok_invalid"
        .parse::<TokenId>()
        .expect_err("malformed TypeID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"capability token id must be a valid TypeID: `ctok_invalid` has an invalid suffix");
}

#[test]
fn type_id_rejects_incorrect_uuid_version() {
    let error = "sbx_2n1t201rmv88eb2sj4cn248g00"
        .parse::<SandboxId>()
        .expect_err("UUID v4 TypeID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"sandbox id must be backed by a UUID v7: `sbx_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4");

    let error = "atok_01j0000000e008000000000001"
        .parse::<ApprovalTokenId>()
        .expect_err("UUID v7 approval TypeID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"approval token id must be backed by a UUID v4: `atok_01j0000000e008000000000001` is backed by a UUID v7");
}

#[test]
fn type_id_rejects_non_rfc_variant() {
    let error = "agt_01j0000000e000000000000001"
        .parse::<AgentId>()
        .expect_err("non-RFC 9562 TypeID variant must be rejected");

    insta::assert_snapshot!(error.to_string(), @"agent id must be backed by an RFC 9562 UUID: `agt_01j0000000e000000000000001` is backed by a UUID with the NCS variant");
}

#[test]
fn type_id_deserialization_runs_validation() {
    let error = serde_json::from_str::<TokenId>(r#""ctok_2n1t201rmv88eb2sj4cn248g00""#)
        .expect_err("deserialization must reject UUID v4 TypeIDs");

    assert_matches!(error.classify(), serde_json::error::Category::Data);
}

#[test]
fn generated_session_id_is_valid() {
    let generated = SessionId::generate();

    assert!(generated.to_string().starts_with("ses_"));
    assert!(generated.to_string().parse::<SessionId>().is_ok());
}

#[test]
fn session_id_accepts_boundaries_and_rejects_invalid_values() {
    assert_matches!(
        "".parse::<SessionId>(),
        Err(firma_identifiers::InvalidSessionIdError::Empty)
    );
    assert_matches!(
        "s;id".parse::<SessionId>(),
        Err(firma_identifiers::InvalidSessionIdError::InvalidFormat)
    );
    assert_matches!(
        "s".repeat(129).parse::<SessionId>(),
        Err(firma_identifiers::InvalidSessionIdError::InvalidFormat)
    );
    assert!("s".parse::<SessionId>().is_ok());
    assert!("s".repeat(128).parse::<SessionId>().is_ok());
}
