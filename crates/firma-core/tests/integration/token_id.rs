use std::assert_matches;
use std::str::FromStr as _;

use chrono::{Duration, Utc};
use firma_core::token::paseto::PasetoV4Verifier;
use firma_core::{CapabilitySeed, TokenError, TokenVerifier};
use firma_identifiers::TokenId;
use pasetors::claims::Claims;
use pasetors::keys::{AsymmetricKeyPair, Generate as _};
use pasetors::version4::{PublicToken, V4};

const TOKEN_ID: &str = "ctok_01j0000000e008000000000001";

#[test]
fn generated_id_is_ctok_typeid() {
    let generated = TokenId::generate();
    assert!(generated.to_string().starts_with("ctok_"));
    assert!(generated.to_string().parse::<TokenId>().is_ok());
}

#[test]
fn display_is_canonical() {
    let id = TokenId::from_str(TOKEN_ID).expect("valid token ID fixture");
    assert_eq!(id.to_string(), TOKEN_ID);
}

#[test]
fn serde_round_trip_uses_a_string() {
    let id = TokenId::from_str(TOKEN_ID).expect("valid token ID fixture");
    let encoded = serde_json::to_string(&id).expect("serialize token ID");
    assert_eq!(encoded, format!("\"{TOKEN_ID}\""));
    assert_eq!(
        serde_json::from_str::<TokenId>(&encoded).expect("deserialize token ID"),
        id
    );
}

#[test]
fn capability_seed_toml_round_trip_uses_a_string() {
    let body = format!(
        r#"raw_token = "v4.public.test"
token_id = "{TOKEN_ID}"
agent_id = "demo-agent"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "*"
issued_at = "2026-04-29T15:00:00Z"
expiry = "2026-04-29T16:00:00Z"
context_hash = "cafebabe"
"#
    );
    let seed: CapabilitySeed = toml::from_str(&body).expect("parse capability seed");
    assert_eq!(seed.token_id.to_string(), TOKEN_ID);
    let encoded = toml::to_string(&seed).expect("serialize capability seed");
    assert!(encoded.contains(&format!("token_id = \"{TOKEN_ID}\"")));
    assert_eq!(
        toml::from_str::<CapabilitySeed>(&encoded).expect("deserialize capability seed"),
        seed
    );
}

#[test]
fn capability_seed_rejects_legacy_uuid_token_id() {
    let body = r#"raw_token = "v4.public.test"
token_id = "01900000-0000-7000-8000-000000000001"
agent_id = "demo-agent"
session_id = "demo-session"
action_set = ["communication.external.send"]
resource_scope = "*"
issued_at = "2026-04-29T15:00:00Z"
expiry = "2026-04-29T16:00:00Z"
context_hash = "cafebabe"
"#;

    let error = toml::from_str::<CapabilitySeed>(body)
        .expect_err("legacy UUID capability seed must be rejected");
    assert!(error.to_string().contains("must start with `ctok`"));
}

#[test]
fn raw_uuid_is_rejected() {
    let error = "01900000-0000-7000-8000-000000000001"
        .parse::<TokenId>()
        .expect_err("raw UUID must be rejected");
    assert!(error.to_string().contains("must start with `ctok`"));
}

#[test]
fn wrong_prefix_is_rejected() {
    let error = "sbx_01j0000000e008000000000001"
        .parse::<TokenId>()
        .expect_err("wrong prefix must be rejected");
    assert!(error.to_string().contains("must start with `ctok`"));
}

#[test]
fn malformed_typeid_suffix_is_rejected() {
    let error = "ctok_invalid"
        .parse::<TokenId>()
        .expect_err("malformed TypeID must be rejected");
    assert!(error.to_string().contains("invalid suffix"));
}

#[test]
fn uuid_v4_backed_typeid_is_rejected() {
    let error = "ctok_2n1t201rmv88eb2sj4cn248g00"
        .parse::<TokenId>()
        .expect_err("UUID v4 TypeID must be rejected");
    assert!(error.to_string().contains("UUID v4"));
}

#[test]
fn non_rfc_variant_is_rejected() {
    let error = "ctok_01j0000000e000000000000001"
        .parse::<TokenId>()
        .expect_err("non-RFC TypeID must be rejected");
    assert!(error.to_string().contains("NCS variant"));
}

#[test]
fn deserialization_invokes_validation() {
    let error = serde_json::from_str::<TokenId>("\"ctok_2n1t201rmv88eb2sj4cn248g00\"")
        .expect_err("deserialization must reject UUID v4 TypeIDs");
    assert_matches!(error.classify(), serde_json::error::Category::Data);
    assert!(error.to_string().contains("UUID v4"));
}

#[test]
fn paseto_verification_rejects_signed_raw_uuid_token_id() {
    let keypair = AsymmetricKeyPair::<V4>::generate().expect("generate keypair");
    let now = Utc::now();
    let mut claims = Claims::new().expect("create claims");
    claims
        .issued_at(&now.to_rfc3339())
        .expect("set issued-at claim");
    claims
        .expiration(&(now + Duration::minutes(5)).to_rfc3339())
        .expect("set expiry claim");
    claims
        .add_additional("token_id", "01900000-0000-7000-8000-000000000001")
        .expect("set token ID claim");
    claims
        .add_additional("agent_id", "agent_abc")
        .expect("set agent ID claim");
    claims
        .add_additional("session_id", "sess_xyz")
        .expect("set session ID claim");
    claims
        .add_additional("context_hash", "deadbeef")
        .expect("set context hash claim");
    claims
        .add_additional("resource_scope", "*")
        .expect("set resource scope claim");
    claims
        .add_additional("action_set", serde_json::json!(["http:GET"]))
        .expect("set action claim");
    let payload = claims.to_string().expect("serialize claims");
    let token =
        PublicToken::sign(&keypair.secret, payload.as_bytes(), None, None).expect("sign claims");
    let verifier = PasetoV4Verifier::try_new(keypair.public.as_bytes()).expect("build verifier");

    let error = verifier
        .verify(&token)
        .expect_err("raw UUID token ID must be rejected");
    assert_matches!(error, TokenError::Malformed { .. });
    assert!(error.to_string().contains("invalid token_id"));
}
