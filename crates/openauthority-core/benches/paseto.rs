#![allow(clippy::unwrap_used)]

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use openauthority_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
use openauthority_core::token::{CapabilityClaims, TokenSigner, TokenVerifier};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;

fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
    (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
}

fn sample_claims() -> CapabilityClaims {
    let now = Utc::now();
    CapabilityClaims {
        token_id: openauthority_core::token::TokenId::new(),
        agent_id: "agent_bench".parse().unwrap(),
        session_id: "sess_bench".parse().unwrap(),
        action_set: vec!["http:GET".to_string(), "tool:execute".to_string()],
        resource_scope: "https://api.example.com/*".to_string(),
        issued_at: now,
        expiry: now + chrono::Duration::seconds(600),
        context_hash: "abcdef1234567890".to_string(),
        budget_ceiling: None,
    }
}

fn bench_sign(c: &mut Criterion) {
    let (sk, _pk) = generate_keypair();
    let signer = PasetoV4Signer::try_new(&sk).unwrap();
    let claims = sample_claims();

    c.bench_function("paseto_v4_sign", |b| {
        b.iter(|| signer.sign(&claims).unwrap());
    });
}

fn bench_verify(c: &mut Criterion) {
    let (sk, pk) = generate_keypair();
    let signer = PasetoV4Signer::try_new(&sk).unwrap();
    let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
    let token = signer.sign(&sample_claims()).unwrap();

    c.bench_function("paseto_v4_verify", |b| {
        b.iter(|| verifier.verify(&token).unwrap());
    });
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
