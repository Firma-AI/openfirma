//! Roundtrip integration tests.
//!
//! Authority signs a real PASETO v4 token → Sidecar Stage 1 verifies the Ed25519
//! signature → Stage 2 CedarPolicyEvaluator evaluates the policy → Assert Allow.
//!
//! These tests exercise the full cryptographic and policy evaluation path without
//! any mocking of the token layer.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;

use chrono::Utc;
use firma_core::decision::DenyReason;
use firma_core::policy::PolicyBundle;
use firma_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
use firma_core::token::{CapabilityClaims, RevocationStore, TokenError, TokenId, TokenSigner};
use firma_sidecar::pipeline::{
    ActionClassRegistry, CapabilityEntry, CapabilityMap, CapabilityValidator, CedarPolicyEvaluator,
    ConstraintEnforcer, EnforcementDecision, EnforcementPipeline, IntentNormalizer,
    MappingRuleConfig, MappingRulesFile, MappingTable, RawRequest,
};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;

struct NoRevocations;
impl RevocationStore for NoRevocations {
    fn is_revoked(&self, _: &TokenId) -> Result<bool, TokenError> {
        Ok(false)
    }
    fn add_revocation(&self, _: &TokenId) -> Result<(), TokenError> {
        Ok(())
    }
}

fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
}

fn permit_all_bundle() -> PolicyBundle {
    PolicyBundle::new(
        "roundtrip-v1".to_string(),
        b"permit(principal, action, resource);".to_vec(),
        vec![],
        30,
    )
}

fn llm_inference_claims(session: &str) -> CapabilityClaims {
    let now = Utc::now();
    CapabilityClaims {
        token_id: TokenId::new(),
        agent_id: "agent_roundtrip".parse().unwrap(),
        session_id: session.parse().unwrap(),
        action_set: vec!["llm.inference".to_string()],
        resource_scope: "*".to_string(),
        issued_at: now,
        expiry: now + chrono::Duration::hours(1),
        context_hash: "roundtrip-ctx-hash".to_string(),
    }
}

fn make_mapping_table(rules: &[MappingRuleConfig]) -> MappingTable {
    let registry = ActionClassRegistry::v0_1();
    let rules_file = MappingRulesFile {
        rules: rules.to_vec(),
    };
    MappingTable::from_config(&rules_file, &registry, true).unwrap_or_else(|e| panic!("{e}"))
}

fn openai_pipeline(
    raw_token: &str,
    pk_bytes: &[u8],
    cedar_eval: CedarPolicyEvaluator,
) -> EnforcementPipeline {
    let verifier_for_map = PasetoV4Verifier::try_new(pk_bytes).unwrap();
    let verifier_for_stage1 = PasetoV4Verifier::try_new(pk_bytes).unwrap();

    let entry = CapabilityEntry::from_raw_token(raw_token, &verifier_for_map).unwrap();
    let capability_map = CapabilityMap::new(vec![entry]);

    let stage1 = CapabilityValidator::new(
        capability_map,
        Box::new(verifier_for_stage1),
        Box::new(NoRevocations),
    );
    let stage2 = ConstraintEnforcer::new(Box::new(cedar_eval));

    let rules = vec![MappingRuleConfig {
        method: Some("POST".to_string()),
        host: "api.openai.com".to_string(),
        path: Some("/v1/chat/completions".to_string()),
        action_class: "llm.inference".to_string(),
    }];
    let normalizer = IntentNormalizer::new(make_mapping_table(&rules));

    EnforcementPipeline::new(normalizer, stage1, stage2)
}

#[test]
fn authority_issues_sidecar_enforces_allow() {
    let (sk, pk) = generate_keypair();
    let claims = llm_inference_claims("sess_roundtrip");
    let expected_token_id = claims.token_id;

    // Authority side: sign a real PASETO v4 token.
    let signer = PasetoV4Signer::try_new(&sk).unwrap();
    let raw_token = signer.sign(&claims).unwrap();
    assert!(raw_token.starts_with("v4.public."), "must be PASETO v4");

    // Sidecar Stage 2: Cedar permit-all policy.
    let cedar_eval = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();

    let pipeline = openai_pipeline(&raw_token, &pk, cedar_eval);

    let request = RawRequest {
        method: "POST".to_string(),
        host: "api.openai.com".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: HashMap::new(),
        body: None,
        is_https: true,
    };

    let decision = pipeline.enforce(&request, "sess_roundtrip".parse().unwrap());
    assert!(decision.is_allow(), "roundtrip must ALLOW");

    if let EnforcementDecision::Allow {
        claims: verified,
        envelope,
    } = decision
    {
        assert_eq!(verified.agent_id.as_ref(), "agent_roundtrip");
        assert_eq!(verified.token_id, expected_token_id);
        assert_eq!(envelope.intent.action_class, "llm.inference");
        assert_eq!(envelope.metadata.agent_id.as_ref(), "agent_roundtrip");
    }
}

#[test]
fn wrong_key_denied_at_stage1() {
    let (sk, pk) = generate_keypair();
    let (_sk2, pk2) = generate_keypair(); // different key pair

    let claims = llm_inference_claims("sess_wrongkey");

    // map_token signed by sk; the CapabilityMap accepts it (verified with pk).
    let map_token = PasetoV4Signer::try_new(&sk).unwrap().sign(&claims).unwrap();

    let cedar_eval = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();

    // Map insertion uses pk (correct key) — insertion succeeds.
    let verifier_for_map = PasetoV4Verifier::try_new(&pk).unwrap();
    let entry = CapabilityEntry::from_raw_token(&map_token, &verifier_for_map).unwrap();
    let capability_map = CapabilityMap::new(vec![entry]);

    // Stage1 verifier uses pk2 (wrong key) — map_token signed by sk fails verification.
    let stage1 = CapabilityValidator::new(
        capability_map,
        Box::new(PasetoV4Verifier::try_new(&pk2).unwrap()),
        Box::new(NoRevocations),
    );
    let rules = vec![MappingRuleConfig {
        method: Some("POST".to_string()),
        host: "api.openai.com".to_string(),
        path: Some("/v1/chat/completions".to_string()),
        action_class: "llm.inference".to_string(),
    }];
    let pipeline = EnforcementPipeline::new(
        IntentNormalizer::new(make_mapping_table(&rules)),
        stage1,
        ConstraintEnforcer::new(Box::new(cedar_eval)),
    );

    let request = RawRequest {
        method: "POST".to_string(),
        host: "api.openai.com".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: HashMap::new(),
        body: None,
        is_https: true,
    };

    let decision = pipeline.enforce(&request, "sess_wrongkey".parse().unwrap());
    assert!(decision.is_deny(), "wrong key must DENY");
    assert_eq!(decision.deny_reason(), Some(DenyReason::TokenInvalid));
}

#[test]
fn forbid_all_policy_denied_at_stage2() {
    let (sk, pk) = generate_keypair();
    let claims = llm_inference_claims("sess_forbid");
    let signer = PasetoV4Signer::try_new(&sk).unwrap();
    let raw_token = signer.sign(&claims).unwrap();

    // Stage 2: Cedar forbid-all policy — valid token, policy denies.
    let forbid_bundle = PolicyBundle::new(
        "forbid-v1".to_string(),
        b"forbid(principal, action, resource);".to_vec(),
        vec![],
        30,
    );
    let cedar_eval = CedarPolicyEvaluator::from_bundle(&forbid_bundle).unwrap();
    let pipeline = openai_pipeline(&raw_token, &pk, cedar_eval);

    let request = RawRequest {
        method: "POST".to_string(),
        host: "api.openai.com".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers: HashMap::new(),
        body: None,
        is_https: true,
    };

    let decision = pipeline.enforce(&request, "sess_forbid".parse().unwrap());
    assert!(decision.is_deny(), "forbid-all policy must DENY");
    assert_eq!(decision.deny_reason(), Some(DenyReason::PolicyDenied));
}
