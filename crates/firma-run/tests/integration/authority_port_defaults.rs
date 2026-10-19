//! Well-known port defaulting for an Authority URL that names no port.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpListener;
use std::time::{Duration, Instant};

use firma_config_loader::CONFIG_FILE_NAME;
use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::error::RunError;
use firma_run::routing::{AutostartFlags, ResolveAuthorityRequest, resolve_authority};

struct PanicPrompt;
impl AuthorityPromptIo for PanicPrompt {
    fn is_tty(&self) -> bool {
        panic!("prompt should not be consulted for a remote Authority");
    }
    fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
        panic!("prompt should not be invoked");
    }
}

/// Hold the gRPC default port, which is where a URL with an unrecognized scheme
/// falls back to.
fn reserve_grpc_default_port() -> TcpListener {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpListener::bind("127.0.0.1:50051") {
            Ok(listener) => return listener,
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("reserve 127.0.0.1:50051: {error}"),
        }
    }
}

/// An `HTTPS://` URL names the same scheme as `https://`, so its default port is
/// 443. Matching the scheme byte-for-byte instead sent the probe to the gRPC
/// default, which reports a reachable Authority whenever anything happens to
/// hold that port.
#[test]
fn an_uppercase_https_url_defaults_to_the_https_port() {
    let _grpc_default = reserve_grpc_default_port();

    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &config_path,
        "[sidecar.authority]\nurl = \"HTTPS://127.0.0.1\"\n",
    )
    .unwrap();
    let identity = firma_run::identity::RunIdentity::new(*super::helper::agent_id(), "test");
    let firma_exe = tmp.path().join("firma-does-not-exist");
    let state_layout = firma_runtime_state::RuntimeLayout::from_root(tmp.path().join("state"));

    let result = resolve_authority(
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
    );

    match result {
        Err(RunError::AuthorityUnreachable { url, .. }) => {
            assert_eq!(url, "HTTPS://127.0.0.1");
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("the probe must not reach the Authority through the gRPC default port"),
    }
}
