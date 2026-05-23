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
use std::time::Duration;

use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::routing::{AutostartFlags, resolve_authority};

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
    let Ok(_listener) = TcpListener::bind("[::1]:50051") else {
        eprintln!("skip: port 50051 not free for the test");
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    std::fs::write(&cfg, "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n").unwrap();

    let identity = firma_run::identity::RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");
    let flags = AutostartFlags {
        sidecar_autostart: false,
        no_autostart: false,
        template_path: None,
        startup_timeout: Duration::from_secs(2),
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        use_http_proxy_sidecar: false,
    };
    let mut prompt = PanicPrompt;
    let result = resolve_authority(
        &identity,
        &runtime_dir,
        &flags,
        &AuthorityCli::Unset,
        "developer",
        Some(cfg.as_path()),
        cfg.parent(),
        &PathBuf::from("/bin/false"),
        &mut prompt,
    );
    match result {
        Err(firma_run::error::RunError::AuthorityTransportAmbiguous { .. }) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected fail-closed transport ambiguity"),
    }
}
