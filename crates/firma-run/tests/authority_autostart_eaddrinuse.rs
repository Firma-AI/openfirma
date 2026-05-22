//! Bind `[::1]:50051` from the test harness, then call
//! `routing::resolve_authority`. The first probe must succeed (test
//! socket answers), so the resolver returns `Local` without a
//! supervisor.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use firma_run::authority::AuthorityCli;
use firma_run::routing::{AutostartFlags, resolve_authority};

#[test]
fn pre_bound_port_short_circuits_to_local() {
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
    let res = resolve_authority(
        &identity,
        &runtime_dir,
        &flags,
        &AuthorityCli::Unset,
        "developer",
        Some(cfg.as_path()),
        &PathBuf::from("/bin/false"),
    )
    .expect("resolve ok");
    assert_eq!(res.url, "http://[::1]:50051");
    assert!(res.supervisor.is_none());
}
