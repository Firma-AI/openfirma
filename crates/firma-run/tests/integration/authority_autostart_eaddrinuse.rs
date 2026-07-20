//! Bind `[::1]:50051` from the test harness with a non-authority listener,
//! then call `routing::resolve_authority`. The resolver must fail closed
//! because local mode cannot prove the transport is plaintext local gRPC.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpListener;
use std::path::PathBuf;

use firma_config_loader::CONFIG_FILE_NAME;
use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::routing::{AutostartFlags, ResolveAuthorityRequest, resolve_authority};

struct PanicPrompt;
impl AuthorityPromptIo for PanicPrompt {
    fn is_tty(&self) -> bool {
        panic!("prompt should not be consulted when the local port is already bound");
    }
    fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
        panic!("prompt should not be invoked");
    }
}

#[test]
fn pre_bound_port_without_plaintext_h2_fails_closed() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(&cfg, format!("[authority]\nlisten_addr = \"{address}\"\n")).unwrap();
    let identity = firma_run::identity::RunIdentity::new(*super::helper::agent_id(), "test");
    let runtime_dir = tmp.path().join("runtime");
    let flags = AutostartFlags::default();
    let firma_exe = PathBuf::from("/bin/false");
    let mut prompt = PanicPrompt;
    let result = resolve_authority(
        ResolveAuthorityRequest {
            identity: &identity,
            runtime_dir: &runtime_dir,
            flags: &flags,
            cli: &AuthorityCli::Unset,
            profile_name: "developer",
            user_config_path: Some(&cfg),
            user_config_dir: cfg.parent(),
            firma_exe: &firma_exe,
            capability_public_key_path: None,
            working_dir: tmp.path(),
        },
        &mut prompt,
    );
    match result {
        Err(firma_run::error::RunError::AuthorityTransportAmbiguous { .. }) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected fail-closed transport ambiguity"),
    }
}
