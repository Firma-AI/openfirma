#![no_main]

use std::sync::OnceLock;

use arbitrary::Arbitrary;
use chrono::Utc;
use firma_core::TokenVerifier;
use firma_sidecar::config::SeedFile;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzSeed {
    raw_token: String,
    token_id: String,
    agent_id: String,
    session_id: String,
    action_set: Vec<String>,
    resource_scope: String,
    context_hash: String,
}

fn static_verifier() -> &'static dyn TokenVerifier {
    static V: OnceLock<Box<dyn TokenVerifier + Send + Sync>> = OnceLock::new();
    let b = V.get_or_init(|| {
        firma_sidecar::startup::build_token_verifier(None)
            .expect("RejectAllVerifier construction is infallible")
    });
    b.as_ref()
}

fuzz_target!(|input: FuzzSeed| {
    let file = SeedFile {
        raw_token: input.raw_token,
        token_id: input.token_id,
        agent_id: input.agent_id,
        session_id: input.session_id,
        action_set: input.action_set,
        resource_scope: input.resource_scope,
        issued_at: Utc::now(),
        expiry: Utc::now(),
        context_hash: input.context_hash,
    };
    let _ = firma_sidecar::startup::seed_into_entry(&file, static_verifier());
});
