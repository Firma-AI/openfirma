//! Verifies that a sidecar started with a real PASETO v4 seed (signed
//! by the same key whose public half is configured) admits a request
//! through Stage 1's token selection + verification path. Locks the
//! demo's capability-seeding contract end-to-end so a regression in
//! either `firma authority issue` or `startup::capability` will trip
//! CI.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::PathBuf;
use std::process::Command;

use firma_config_loader::CONFIG_FILE_NAME;
use firma_sidecar::config::CapabilitySeedConfig;
use firma_sidecar::startup::{build_token_verifier, load_capability_map};

fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

#[test]
fn issued_token_seeds_capability_map_and_admits_stage1() {
    let tmp = tempfile::tempdir().unwrap();

    // Stage the Cedar policy bundle the authority will load.
    let policies = tmp.path().join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    std::fs::write(
        policies.join("default.cedar"),
        "permit(principal, action, resource);",
    )
    .unwrap();
    std::fs::write(
        policies.join("schema.cedarschema"),
        firma_core::cedar::FIRMA_SCHEMA,
    )
    .unwrap();

    // 1. Generate the Ed25519 key pair via `firma authority generate-key`.
    let key_path = tmp.path().join("firma-authority.key");
    let pub_path: PathBuf = key_path.with_extension("pub");
    let status = Command::new(firma_bin())
        .args(["authority", "generate-key", "--output"])
        .arg(&key_path)
        .current_dir(tmp.path())
        .status()
        .unwrap();
    assert!(status.success(), "generate-key failed");
    assert!(key_path.exists(), "private key file missing");
    assert!(pub_path.exists(), "public key file missing");

    // 2. Write a unified sectioned firma.toml that points at the
    //    policies + key; `firma authority` resolves `[authority]` via the
    //    strict section loader.
    let auth_toml = tmp.path().join(CONFIG_FILE_NAME);
    let revocation_file = tmp.path().join("revocations.txt");
    std::fs::write(
        &auth_toml,
        format!(
            "[authority]\n\
             listen_addr = \"127.0.0.1:0\"\n\
             policy_dir = {policy_dir}\n\
             revocation_file = {revocation}\n\
             max_ttl_seconds = 3600\n\
             key_file = {key_file}\n\
             log_level = \"warn\"\n\
             bundle_ttl_seconds = 30\n",
            policy_dir = toml::Value::String(policies.to_string_lossy().into_owned()),
            revocation = toml::Value::String(revocation_file.to_string_lossy().into_owned()),
            key_file = toml::Value::String(key_path.to_string_lossy().into_owned()),
        ),
    )
    .unwrap();

    // 3. Issue a capability seed file via `firma authority issue`.
    let seed_path = tmp.path().join("capability.toml");
    let status = Command::new(firma_bin())
        .args(["authority", "--config"])
        .arg(&auth_toml)
        .args([
            "issue",
            "--agent-id",
            "agt_01j0000000e008000000000001",
            "--session-id",
            "test-session",
            "--action",
            "communication.external.send",
            "--resource-scope",
            "*",
            "--ttl-seconds",
            "300",
            "--output",
        ])
        .arg(&seed_path)
        .status()
        .unwrap();
    assert!(status.success(), "issue subcommand failed");
    assert!(seed_path.exists(), "issue did not create the seed file");

    // 4. Build the verifier from the public key the authority just wrote.
    let verifier = build_token_verifier(Some(pub_path.as_path())).expect("verifier must build");

    // 5. Load the capability map from the seed file. Seed loading verifies
    // the raw PASETO token before adding it to the map.
    let seed = CapabilitySeedConfig {
        paths: vec![seed_path],
        hot_reload: true,
    };
    // Pass a separate capabilities_dir so the seed path is treated as an
    // operator seed (outside the runtime capabilities directory).
    let capabilities_dir = tmp.path().join("capabilities");
    let map =
        load_capability_map(&seed, verifier.as_ref(), &capabilities_dir).expect("seed must load");

    // 6. Selecting the seeded action class returns the seed entry.
    let entry = map
        .select(
            "test-session",
            "communication.external.send",
            "wttr.in/Berlin",
        )
        .expect("seeded entry must select");

    // The seed file must round-trip through the verifier — this proves
    // the public key matches the private key the CLI signed with.
    let claims = verifier
        .verify(&entry.raw_token)
        .expect("token must verify against the issued public key");
    assert_eq!(
        claims.agent_id.to_string(),
        "agt_01j0000000e008000000000001"
    );
    assert_eq!(claims.session_id.to_string(), "test-session");
    assert_eq!(claims.action_set, vec!["communication.external.send"]);
}
