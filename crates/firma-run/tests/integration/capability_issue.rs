//! Failure-path coverage for capability minting
//! ([`firma_run::capability::issue::mint_and_write`]).
//!
//! The success path needs a live Authority (covered by `capability_mint`); these
//! tests drive the local, network-free failure modes `mint()` guards before and
//! around the `IssueCapability` RPC: an unreadable/invalid Authority public key,
//! and an unreachable Authority. None must leave a seed file behind.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::{Path, PathBuf};

use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;

use firma_run::capability::issue::{IssueParams, mint_and_write};

fn params(authority_url: &str, pub_key_path: PathBuf) -> IssueParams {
    IssueParams {
        authority_url: authority_url.to_string(),
        authority_pub_key_path: pub_key_path,
        authority_ca_cert_path: None,
        credentials: None,
        agent_id: "agent_issue".to_string(),
        session_id: "sess_issue".to_string(),
        requested_actions: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        ttl_seconds: 900,
    }
}

/// Write a valid Ed25519 Authority public key to `dir/authority.pub`.
fn write_valid_public_key(dir: &Path) -> PathBuf {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    let path = dir.join("authority.pub");
    std::fs::write(&path, kp.public.as_bytes()).expect("write pubkey");
    path
}

#[test]
fn mint_fails_when_public_key_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(
        &params("http://127.0.0.1:1", dir.path().join("absent.pub")),
        &seed_path,
    )
    .expect_err("missing public key must fail");

    assert!(err.to_string().contains("public key"), "got: {err}");
    assert!(!seed_path.exists(), "no seed should be written on failure");
}

#[test]
fn mint_fails_on_invalid_public_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bad_key = dir.path().join("authority.pub");
    // Too short to be an Ed25519 public key.
    std::fs::write(&bad_key, b"not-a-key").expect("write bad key");
    let seed_path = dir.path().join("seed.toml");

    let err = mint_and_write(&params("http://127.0.0.1:1", bad_key), &seed_path)
        .expect_err("invalid public key must fail");

    assert!(
        err.to_string().contains("invalid authority public key"),
        "got: {err}"
    );
    assert!(!seed_path.exists(), "no seed should be written on failure");
}

#[test]
fn mint_fails_when_authority_unreachable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pub_key = write_valid_public_key(dir.path());
    let seed_path = dir.path().join("seed.toml");

    // Valid key clears local verification; the RPC then fails fast against a
    // closed loopback port, exercising the runtime/channel/RPC error path. It
    // must surface a typed error rather than panic, and write no seed.
    mint_and_write(&params("http://127.0.0.1:1", pub_key), &seed_path)
        .expect_err("unreachable authority must fail");

    assert!(!seed_path.exists(), "no seed should be written on failure");
}
