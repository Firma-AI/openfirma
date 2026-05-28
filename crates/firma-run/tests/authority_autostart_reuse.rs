//! When a plaintext H2 listener is already up on `[::1]:50051`, `resolve_authority`
//! must take the reuse path: return `supervisor: None` and not attempt autostart.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::routing::{AutostartFlags, resolve_authority};

struct NoPrompt;
impl AuthorityPromptIo for NoPrompt {
    fn is_tty(&self) -> bool {
        false
    }
    fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
        panic!("prompt must not be called on reuse path");
    }
}

/// Minimal plaintext-H2 stub: accepts connections in a loop.
///
/// `probe_authority_tcp` and `probe_authority_plaintext_h2` each open a
/// separate TCP connection. The TCP probe sends no data; the H2 probe sends
/// the 24-byte preface and expects at least one byte back.
///
/// A short read timeout lets us skip the data-less TCP probe without blocking.
fn spawn_plaintext_h2_stub(listener: TcpListener) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let mut buf = [0u8; 24];
            if stream.read_exact(&mut buf).is_ok() {
                let _ = std::io::Write::write_all(&mut stream, b"\x00");
            }
            // TCP-probe connections send no data → read_exact times out → drop.
        }
    });
}

#[test]
fn existing_plaintext_h2_authority_is_reused_without_supervisor() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let authority_address = listener.local_addr().unwrap();
    spawn_plaintext_h2_stub(listener);

    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("firma.toml");
    std::fs::write(&cfg, format!("[authority]\nlisten_addr = \"{authority_address}\"\n")).unwrap();
    let identity = firma_run::identity::RunIdentity::new("test");
    let runtime_dir = tmp.path().join("runtime");
    let flags = AutostartFlags::default();
    let mut prompt = NoPrompt;
    let result = resolve_authority(
        &identity,
        &runtime_dir,
        &flags,
        &AuthorityCli::Unset,
        "developer",
        Some(&cfg),
        cfg.parent(),
        &PathBuf::from("/bin/false"),
        &mut prompt,
    );

    let resolved = result.expect("reuse path should succeed");
    assert!(
        resolved.supervisor.is_none(),
        "reuse path must not spawn a supervisor"
    );
    assert_eq!(resolved.url, format!("http://{authority_address}"));
}
