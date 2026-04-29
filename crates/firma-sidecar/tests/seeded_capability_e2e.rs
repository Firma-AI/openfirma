//! Verifies that a sidecar started with a real PASETO v4 seed (signed
//! by the same key whose public half is configured) admits a request
//! through Stage 1's token selection + verification path. Locks the
//! demo's capability-seeding contract end-to-end so a regression in
//! either `firma-authority issue` or `startup::capability` will trip
//! CI.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use firma_sidecar::config::CapabilitySeedConfig;
use firma_sidecar::startup::{build_token_verifier, load_capability_map};

/// Build the `firma-authority` binary and return the absolute path to
/// the produced executable. We cannot rely on `CARGO_BIN_EXE_*` here
/// because it is only populated for integration tests living in the
/// same package as the binary target; `firma-authority` lives in a
/// sibling crate.
fn build_authority_bin() -> PathBuf {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .args([
            "build",
            "-p",
            "firma-authority",
            "--bin",
            "firma-authority",
            "--quiet",
        ])
        .status()
        .expect("cargo build firma-authority");
    assert!(status.success(), "cargo build firma-authority failed");

    // `CARGO_MANIFEST_DIR` is `crates/firma-sidecar`; the workspace
    // target directory is two levels up unless the user has overridden
    // it via `CARGO_TARGET_DIR`.
    let target_dir = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(std::path::Path::parent)
                .expect("workspace root")
                .join("target")
        },
        PathBuf::from,
    );
    let exe_name = if cfg!(windows) {
        "firma-authority.exe"
    } else {
        "firma-authority"
    };
    let bin = target_dir.join("debug").join(exe_name);
    assert!(
        bin.exists(),
        "firma-authority binary missing at {}",
        bin.display()
    );
    bin
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
    let schema_src = include_str!("../../firma-authority/schema.cedarschema");
    std::fs::write(policies.join("schema.cedarschema"), schema_src).unwrap();

    // Resolve (and ensure) the firma-authority binary. Cargo does not
    // set `CARGO_BIN_EXE_firma-authority` for tests outside that bin's
    // own package, so we trigger the build explicitly.
    let auth_bin = build_authority_bin();

    // 1. Generate the Ed25519 key pair. `generate-key` writes the
    //    private key to <output> and the public key to
    //    <output with .pub extension> (see `run_generate_key`).
    let key_path = tmp.path().join("firma-authority.key");
    let pub_path: PathBuf = key_path.with_extension("pub");
    let status = Command::new(&auth_bin)
        .args(["generate-key", "--output"])
        .arg(&key_path)
        .current_dir(tmp.path())
        .status()
        .unwrap();
    assert!(status.success(), "generate-key failed");
    assert!(key_path.exists(), "private key file missing");
    assert!(pub_path.exists(), "public key file missing");

    // 2. Write an authority TOML that points at the policies + key.
    let auth_toml = tmp.path().join("authority.toml");
    let revocation_file = tmp.path().join("revocations.txt");
    std::fs::write(
        &auth_toml,
        format!(
            "listen_addr = \"127.0.0.1:0\"\n\
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

    // 3. Issue a capability seed file via the CLI subcommand.
    let seed_path = tmp.path().join("capability.toml");
    let status = Command::new(&auth_bin)
        .arg("--config")
        .arg(&auth_toml)
        .args([
            "issue",
            "--agent-id",
            "test-agent",
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

    // 4. Load the capability map from the seed file.
    let seed = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
    };
    let map = load_capability_map(&seed).expect("seed must load");

    // 5. Build the verifier from the public key the authority just
    //    wrote.
    let verifier = build_token_verifier(Some(pub_path.as_path())).expect("verifier must build");

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
    assert_eq!(claims.agent_id.to_string(), "test-agent");
    assert_eq!(claims.session_id.to_string(), "test-session");
    assert_eq!(claims.action_set, vec!["communication.external.send"]);
}
