use std::assert_matches;
use std::str::FromStr as _;

use firma_identifiers::AgentId;

const AGENT_ID: &str = "agt_01j0000000e008000000000001";

#[test]
fn generated_id_is_agt_typeid() {
    let generated = AgentId::generate();
    assert!(generated.to_string().starts_with("agt_"));
    assert!(generated.to_string().parse::<AgentId>().is_ok());
}

#[test]
fn display_is_canonical() {
    let id = AgentId::from_str(AGENT_ID).expect("valid agent ID fixture");
    assert_eq!(id.to_string(), AGENT_ID);
}

#[test]
fn serde_round_trip_uses_a_string() {
    let id = AgentId::from_str(AGENT_ID).expect("valid agent ID fixture");
    let encoded = serde_json::to_string(&id).expect("serialize agent id");
    assert_eq!(encoded, format!("\"{AGENT_ID}\""));
    assert_eq!(
        serde_json::from_str::<AgentId>(&encoded).expect("deserialize agent id"),
        id
    );
}

#[test]
fn malformed_typeid_is_rejected() {
    let error = "agt_invalid"
        .parse::<AgentId>()
        .expect_err("malformed TypeID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"agent id must be a valid TypeID: `agt_invalid` has an invalid suffix");
}

#[test]
fn raw_uuid_is_rejected() {
    let error = "01900000-0000-7000-8000-000000000001"
        .parse::<AgentId>()
        .expect_err("raw UUID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"agent id must start with `agt` as prefix: `01900000-0000-7000-8000-000000000001` does not");
}

#[test]
fn incorrect_prefix_is_rejected() {
    let error = "sbx_01j0000000e008000000000001"
        .parse::<AgentId>()
        .expect_err("sandbox TypeID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"agent id must start with `agt` as prefix: `sbx_01j0000000e008000000000001` does not");
}

#[test]
fn non_v7_typeid_is_rejected() {
    let error = "agt_2n1t201rmv88eb2sj4cn248g00"
        .parse::<AgentId>()
        .expect_err("non-v7 TypeID must be rejected");

    insta::assert_snapshot!(error.to_string(), @"agent id must be backed by a UUID v7: `agt_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4");
}

#[test]
fn non_rfc_9562_variant_is_rejected() {
    let error = "agt_01j0000000e000000000000001"
        .parse::<AgentId>()
        .expect_err("non-RFC 9562 TypeID variant must be rejected");

    insta::assert_snapshot!(error.to_string(), @"agent id must be backed by an RFC 9562 UUID: `agt_01j0000000e000000000000001` is backed by a UUID with the NCS variant");
}

#[test]
fn deserialization_rejects_non_v7_typeid() {
    let encoded = "\"agt_2n1t201rmv88eb2sj4cn248g00\"";
    let error = serde_json::from_str::<AgentId>(encoded)
        .expect_err("deserialization must reject non-v7 agent IDs");

    assert_matches!(error.classify(), serde_json::error::Category::Data);
    insta::assert_snapshot!(error.to_string(), @"agent id must be backed by a UUID v7: `agt_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4");
}
