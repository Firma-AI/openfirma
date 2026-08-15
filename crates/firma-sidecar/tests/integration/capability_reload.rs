//! Integration coverage for the Stage 1 capability seed hot-reload watcher
//! ([`firma_sidecar::startup::capability::CapabilityReloader`]).
//!
//! Exercises the real file watcher + async reload loop: a re-minted seed is
//! hot-swapped into the live `CapabilityMap`, while a removed or invalid seed
//! leaves the previous map in place (fail-closed on the token's own expiry).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use firma_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
use firma_core::{CapabilityClaims, CapabilitySeed, TokenSigner, TokenVerifier};
use firma_identifiers::TokenId;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio_util::sync::CancellationToken;

use firma_sidecar::config::CapabilitySeedConfig;
use firma_sidecar::enforcement::capability_validation::CapabilityMapHandle;
use firma_sidecar::startup::capability::{CapabilityReloader, load_capability_map};

const SESSION: &str = "sess_reload";
const ACTION: &str = "communication.external.send";
const RESOURCE: &str = "wttr.in";

struct Keys {
    signer: PasetoV4Signer,
    public: Vec<u8>,
}

fn keys() -> Keys {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    Keys {
        signer: PasetoV4Signer::try_new(kp.secret.as_bytes()).expect("signer"),
        public: kp.public.as_bytes().to_vec(),
    }
}

fn verifier(public: &[u8]) -> Arc<dyn TokenVerifier + Send + Sync> {
    Arc::new(PasetoV4Verifier::try_new(public).expect("verifier"))
}

fn claims(expiry: DateTime<Utc>) -> CapabilityClaims {
    let now = Utc::now();
    CapabilityClaims {
        token_id: TokenId::generate(),
        agent_id: "agt_01j0000000e008000000000001".parse().expect("agent id"),
        session_id: SESSION.parse().expect("session id"),
        action_set: vec![ACTION.to_string()],
        resource_scope: "*".to_string(),
        issued_at: now,
        expiry,
        context_hash: "deadbeef".to_string(),
    }
}

/// Sign fresh claims and return the seed plus the raw token it carries.
fn signed_seed(signer: &PasetoV4Signer) -> (CapabilitySeed, String) {
    let claims = claims(Utc::now() + chrono::Duration::minutes(15));
    let raw_token = signer.sign(&claims).expect("sign");
    (
        CapabilitySeed::from_claims(&claims, raw_token.clone()),
        raw_token,
    )
}

/// Atomically write `seed` to `target` (temp file + rename in the same dir),
/// mirroring how `firma run` re-mints the seed.
fn write_seed(dir: &Path, target: &Path, seed: &CapabilitySeed) {
    let body = toml::to_string(seed).expect("serialize seed");
    let tmp = dir.join("seed.tmp");
    std::fs::write(&tmp, body).expect("write temp seed");
    std::fs::rename(&tmp, target).expect("rename seed into place");
}

fn handle_from(
    seed_config: &CapabilitySeedConfig,
    verifier: &Arc<dyn TokenVerifier + Send + Sync>,
    dir: &Path,
) -> CapabilityMapHandle {
    let map = load_capability_map(seed_config, verifier.as_ref(), dir).expect("initial map");
    CapabilityMapHandle::new(map)
}

fn selected_raw_token(handle: &CapabilityMapHandle) -> Option<String> {
    handle
        .load()
        .select(SESSION, ACTION, RESOURCE)
        .ok()
        .map(|entry| entry.raw_token.clone())
}

/// Poll the live map until `select` resolves to `expected` (or time out).
async fn wait_for_token(handle: &CapabilityMapHandle, expected: &str) -> bool {
    for _ in 0..100 {
        if selected_raw_token(handle).as_deref() == Some(expected) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn reload_hot_swaps_map_on_seed_rewrite() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let (seed_v1, raw_v1) = signed_seed(&keys.signer);
    write_seed(dir.path(), &seed_path, &seed_v1);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, dir.path());
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_v1.as_str())
    );

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    // Re-mint: a distinct token for the same selection key.
    let (seed_v2, raw_v2) = signed_seed(&keys.signer);
    assert_ne!(raw_v1, raw_v2, "re-mint must produce a distinct token");
    write_seed(dir.path(), &seed_path, &seed_v2);

    assert!(
        wait_for_token(&handle, &raw_v2).await,
        "map should hot-swap to the re-minted token"
    );

    cancel.cancel();
}

#[tokio::test]
async fn reload_keeps_previous_map_when_seed_removed() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let (seed_v1, raw_v1) = signed_seed(&keys.signer);
    write_seed(dir.path(), &seed_path, &seed_v1);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, dir.path());

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    // Teardown deletes the seed; the watcher must keep the previous map rather
    // than swapping in an empty one.
    std::fs::remove_file(&seed_path).expect("remove seed");

    // Give the watcher time to observe and process the Remove event.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_v1.as_str()),
        "removing the seed must not drop the live capability map"
    );

    cancel.cancel();
}

#[tokio::test]
async fn reload_keeps_previous_map_on_invalid_seed() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let (seed_v1, raw_v1) = signed_seed(&keys.signer);
    write_seed(dir.path(), &seed_path, &seed_v1);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, dir.path());

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    // A rewrite whose mirror parses but whose raw_token fails verification must
    // not be installed; the previous valid map is retained.
    let mut tampered = seed_v1.clone();
    tampered.raw_token = "v4.public.not-a-valid-token".to_string();
    write_seed(dir.path(), &seed_path, &tampered);

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_v1.as_str()),
        "an unverifiable re-mint must not replace the live map"
    );

    cancel.cancel();
}
