use firma_protobuf::v1::RevocationEvent;
use firma_sidecar::authority_client::revocation::token_id_from_event;

#[test]
fn protobuf_revocation_accepts_ctok_id() {
    let event = RevocationEvent {
        token_id: "ctok_01j0000000e008000000000001".to_string(),
        ..Default::default()
    };

    let token_id = token_id_from_event(&event).expect("valid revocation token ID");
    assert_eq!(token_id.to_string(), event.token_id);
}

#[test]
fn protobuf_revocation_rejects_raw_uuid() {
    let event = RevocationEvent {
        token_id: "01900000-0000-7000-8000-000000000001".to_string(),
        ..Default::default()
    };

    let error = token_id_from_event(&event).expect_err("raw UUID must be rejected");
    assert!(error.contains("must start with `ctok`"));
}
