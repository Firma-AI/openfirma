//! State-directory TLS anchor adoption in `routing::resolve_authority`.
//!
//! A config that names no CA certificate adopts the one in the state directory,
//! and a local Authority whose material was wiped has it regenerated. Neither
//! may happen for an Authority this host does not own: its CA is issued
//! elsewhere, so there is nothing local to repair.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpListener;

use firma_config_loader::CONFIG_FILE_NAME;
use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::error::RunError;
use firma_run::routing::{
    AutostartFlags, ResolveAuthorityRequest, ResolvedAuthority, resolve_authority,
};

struct PanicPrompt;
impl AuthorityPromptIo for PanicPrompt {
    fn is_tty(&self) -> bool {
        panic!("prompt should not be consulted");
    }
    fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
        panic!("prompt should not be invoked");
    }
}

/// Resolve against `config_body`, with a `firma` executable that cannot be
/// spawned. Any attempt to regenerate TLS material therefore surfaces as
/// `RunError::Internal`, which is how each test observes whether the
/// regeneration path was entered.
fn resolve(config_body: &str) -> Result<ResolvedAuthority, RunError> {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(&config_path, config_body).unwrap();
    let identity = firma_run::identity::RunIdentity::new(*super::helper::agent_id(), "test");
    let firma_exe = tmp.path().join("firma-does-not-exist");
    let state_layout = firma_runtime_state::RuntimeLayout::from_root(tmp.path().join("state"));

    resolve_authority(
        ResolveAuthorityRequest {
            identity: &identity,
            flags: &AutostartFlags::default(),
            cli: &AuthorityCli::Unset,
            profile_name: "developer",
            user_config_path: Some(&config_path),
            user_config_dir: config_path.parent(),
            firma_exe: &firma_exe,
            capability_public_key_path: None,
            working_dir: tmp.path(),
            state_layout: &state_layout,
        },
        &mut PanicPrompt,
    )
}

/// A remote `https://` Authority owns its own TLS identity. Adopting the
/// state-directory CA position for it turns every run into a local
/// `firma authority init-tls` invocation: on failure the run dies, and on
/// success the Sidecar pins a CA this host just minted against a server that
/// was never issued a certificate by it.
#[test]
fn a_remote_https_authority_neither_adopts_nor_regenerates_local_tls_material() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let resolved = resolve(&format!(
        "[sidecar.authority]\nurl = \"https://{address}\"\n"
    ))
    .expect("a remote https Authority must resolve without local TLS regeneration");

    assert_eq!(
        resolved.ca_cert_path, None,
        "a config that pinned no CA must not acquire the local state-directory one for a remote Authority"
    );
}

/// The recovery path itself: a local Authority reached over TLS whose CA
/// certificate is gone (a wiped `XDG_RUNTIME_DIR`) still has its material
/// regenerated, even though the config names no `ca_cert_path`.
#[test]
fn a_local_tls_authority_regenerates_its_wiped_ca_material() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let result = resolve(&format!(
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"{address}\"\n\n[sidecar.authority]\nurl = \"https://{address}\"\n"
    ));

    match result {
        Err(RunError::Internal(message)) => assert!(
            message.contains("init-tls"),
            "expected a TLS regeneration attempt, got: {message}"
        ),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("regeneration must be attempted through the configured firma executable"),
    }
}

/// URL schemes are case-insensitive, and the Sidecar reads them through a URI
/// parser that normalizes them: it treats `HTTPS://` as TLS and refuses to start
/// without a CA certificate. A byte-prefix test here disagrees, so the run skips
/// the recovery and then dies on the Sidecar's own validation instead.
#[test]
fn an_uppercase_https_scheme_still_triggers_tls_recovery() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let result = resolve(&format!(
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"{address}\"\n\n[sidecar.authority]\nurl = \"HTTPS://{address}\"\n"
    ));

    match result {
        Err(RunError::Internal(message)) => assert!(
            message.contains("init-tls"),
            "expected a TLS regeneration attempt, got: {message}"
        ),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("an uppercase https scheme must be recognized as TLS"),
    }
}

/// An `http://` local Authority has no TLS identity to repair, so the CA
/// position in the state directory stays unclaimed.
#[test]
fn a_plaintext_local_authority_claims_no_ca_position() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();

    let resolved = resolve(&format!(
        "[sidecar.authority]\nurl = \"http://{address}\"\n"
    ))
    .expect("a plaintext Authority must resolve");

    assert_eq!(resolved.ca_cert_path, None);
}
