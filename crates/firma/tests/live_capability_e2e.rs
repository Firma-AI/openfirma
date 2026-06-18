//! End-to-end coverage for `firma run`'s live capability minting (FIR-186).
//!
//! Two scenarios are exercised against the real new code paths:
//!
//! - Test A (`live_mint_writes_seed_and_admits_stage1`): a real Mini Authority
//!   is booted over plaintext loopback gRPC. `firma_run`'s
//!   [`mint_and_write`] calls the live `IssueCapability` RPC, verifies the
//!   returned token locally, and writes the seed to the deterministic runtime
//!   path (`<FIRMA_STATE_DIR>/capabilities/<sandbox_id>.toml`). The seed is
//!   then loaded through the sidecar's capability map and shown to ALLOW the
//!   default action — the same Stage 1 admission proof used by
//!   `seeded_capability_e2e.rs`.
//! - Test B (`no_autostart_unreachable_authority_fails_loudly`): the
//!   `--no-autostart` authority-resolution path is driven against a closed
//!   port and must fail with the typed [`RunError::AuthorityUnreachable`].
//!
//! ## Why the full `firma run` CLI is not driven here
//!
//! `firma_run::runtime::execute_run` resolves the Authority only AFTER
//! `backend.prepare` + `backend.enforce_network`. On hosts without a
//! structural sandbox backend (e.g. macOS, where Linux bwrap is unavailable)
//! the run aborts on the backend before authority resolution, so the full CLI
//! cannot surface `AuthorityUnreachable` or reach the live mint. These tests
//! therefore drive the exact public functions that implement the new
//! behaviour (`mint_and_write`, `resolve_authority`) directly, which keeps the
//! assertions deterministic and host-independent while still exercising real
//! gRPC issuance and the real typed error path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code: panics are acceptable test failures"
)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use firma_sidecar::config::CapabilitySeedConfig;
use firma_sidecar::startup::{build_token_verifier, load_capability_map};

const READY_TIMEOUT: Duration = Duration::from_secs(15);

fn firma_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

/// Bind, capture, and immediately release a loopback port so callers can hand
/// the now-free address to code that expects nothing listening on it.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// A booted Mini Authority listening on plaintext loopback gRPC. Holds the
/// child handle so the server is killed on drop.
struct LiveAuthority {
    child: Child,
    url: String,
    pub_key_path: PathBuf,
    logs: std::sync::Arc<std::sync::Mutex<String>>,
    _tmp: tempfile::TempDir,
}

impl Drop for LiveAuthority {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Boot `firma authority` against a permit-all Cedar bundle on a random
/// loopback port, scraping the resolved address from the ready contract.
fn spawn_live_authority() -> LiveAuthority {
    let tmp = tempfile::tempdir().unwrap();

    // Permit-all Cedar bundle: issuance evaluates the same bundle the sidecar
    // would, so a bare `permit` grants the requested action.
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

    // The Mini Authority requires a separate issuance policy bundle and refuses
    // to start if its directory is missing. A bare `permit` grants issuance.
    let issuance_policies = tmp.path().join("issuance-policies");
    std::fs::create_dir_all(&issuance_policies).unwrap();
    std::fs::write(
        issuance_policies.join("default.cedar"),
        "permit(principal, action, resource);",
    )
    .unwrap();
    std::fs::write(
        issuance_policies.join("schema.cedarschema"),
        firma_core::cedar::FIRMA_SCHEMA,
    )
    .unwrap();

    let key_path = tmp.path().join("firma-authority.key");
    let pub_key_path = key_path.with_extension("pub");
    let status = Command::new(firma_bin())
        .args(["authority", "generate-key", "--output"])
        .arg(&key_path)
        .current_dir(tmp.path())
        .status()
        .unwrap();
    assert!(status.success(), "generate-key failed");

    let revocation_file = tmp.path().join("revocations.txt");
    let auth_toml = tmp.path().join("firma.toml");
    std::fs::write(
        &auth_toml,
        format!(
            "[authority]\n\
             listen_addr = \"127.0.0.1:0\"\n\
             policy_dir = {policy_dir}\n\
             issuance_policy_dir = {issuance_policy_dir}\n\
             revocation_file = {revocation}\n\
             max_ttl_seconds = 3600\n\
             key_file = {key_file}\n\
             log_level = \"info\"\n\
             bundle_ttl_seconds = 30\n",
            policy_dir = toml::Value::String(policies.to_string_lossy().into_owned()),
            issuance_policy_dir =
                toml::Value::String(issuance_policies.to_string_lossy().into_owned()),
            revocation = toml::Value::String(revocation_file.to_string_lossy().into_owned()),
            key_file = toml::Value::String(key_path.to_string_lossy().into_owned()),
        ),
    )
    .unwrap();

    let mut child = Command::new(firma_bin())
        .args(["authority", "--config"])
        .arg(&auth_toml)
        .env("FIRMA_LOG_FILTER", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn firma authority");

    let mut stderr = BufReader::new(child.stderr.take().expect("stderr pipe"));
    let addr = scrape_listening_addr(&mut stderr).unwrap_or_else(|| {
        let _ = child.kill();
        panic!("authority did not log its listening addr within timeout");
    });

    // Keep draining stderr into a shared buffer so server-side errors during
    // the RPC are observable when an assertion fails.
    let logs = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let drain_logs = std::sync::Arc::clone(&logs);
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match stderr.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if let Ok(mut guard) = drain_logs.lock() {
                        guard.push_str(&line);
                    }
                }
            }
        }
    });

    LiveAuthority {
        child,
        url: format!("http://{addr}"),
        pub_key_path,
        logs,
        _tmp: tmp,
    }
}

/// Read the authority's stderr until the `listening addr="…"` ready line is
/// seen, returning the resolved socket address (the random port).
fn scrape_listening_addr<R>(buf: &mut R) -> Option<String>
where
    R: BufRead,
{
    let mut line = String::new();
    let start = Instant::now();
    while start.elapsed() < READY_TIMEOUT {
        line.clear();
        match buf.read_line(&mut line) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                if let Some(addr) = parse_listening_addr(&line) {
                    return Some(addr);
                }
            }
        }
    }
    None
}

/// Extract the value of the `addr=` field from the authority's `listening`
/// log line. The CLI renderer emits the field unquoted
/// (`listening addr=127.0.0.1:60417`), so the value runs to the next
/// whitespace; a surrounding pair of quotes is tolerated and stripped.
fn parse_listening_addr(line: &str) -> Option<String> {
    if !line.contains("listening") {
        return None;
    }
    let rest = line.split("addr=").nth(1)?;
    let addr = rest
        .split_whitespace()
        .next()?
        .trim_matches('"')
        .trim_end_matches(',');
    if addr.is_empty() {
        None
    } else {
        Some(addr.to_string())
    }
}

/// Test A: live mint → seed written → Stage 1 admits the default action.
#[test]
fn live_mint_writes_seed_and_admits_stage1() {
    let authority = spawn_live_authority();

    // Pin the runtime dir and sandbox id so the seed path is deterministic and
    // matches what `firma run`'s autostart mint would compute.
    let state_dir = tempfile::tempdir().unwrap();
    let sandbox_id = "live-mint-sandbox";
    let runtime_dir = state_dir.path();
    let seed_path = runtime_dir
        .join("capabilities")
        .join(format!("{sandbox_id}.toml"));

    // Sanity: this is the same path `firma_stack` resolves for the pinned
    // FIRMA_STATE_DIR, so the assertion below tracks the production location.
    let resolved_runtime = firma_stack::runtime_paths::default_runtime_dir_from(
        None,
        Some(runtime_dir.to_string_lossy().into_owned()),
        None,
        0,
    );
    let resolved_seed = firma_stack::runtime_paths::capabilities_dir_from(&resolved_runtime)
        .join(format!("{sandbox_id}.toml"));
    assert_eq!(
        resolved_seed, seed_path,
        "seed path must match the runtime-path helper for the pinned state dir"
    );

    // Mint against the live Authority: real IssueCapability RPC + local verify
    // + atomic seed write. No operator `[capability_seed]` is involved.
    let params = firma_run::capability::issue::IssueParams {
        authority_url: authority.url.clone(),
        authority_pub_key_path: authority.pub_key_path.clone(),
        authority_ca_cert_path: None,
        agent_id: "live-agent".to_string(),
        session_id: "live-session".to_string(),
        requested_actions: firma_run::capability::issue::DEFAULT_REQUESTED_ACTIONS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        resource_scope: firma_run::capability::issue::DEFAULT_RESOURCE_SCOPE.to_string(),
        ttl_seconds: firma_run::capability::issue::DEFAULT_TTL_SECONDS,
    };
    let written =
        firma_run::capability::issue::mint_and_write(&params, &seed_path).unwrap_or_else(|e| {
            let logs = authority.logs.lock().map(|g| g.clone()).unwrap_or_default();
            panic!("live mint failed: {e}\n--- authority logs ---\n{logs}");
        });
    assert_eq!(written, seed_path);
    assert!(
        seed_path.exists(),
        "minted seed file must exist at {}",
        seed_path.display()
    );

    // Build the verifier from the Authority's published public key and load the
    // freshly minted seed through the sidecar's capability map — the same
    // Stage 1 admission path proven by `seeded_capability_e2e.rs`.
    let verifier =
        build_token_verifier(Some(authority.pub_key_path.as_path())).expect("verifier must build");
    let seed_cfg = CapabilitySeedConfig {
        paths: vec![seed_path],
    };
    // A separate capabilities_dir keeps the seed path classified as an operator
    // seed for loading purposes (the live path under FIRMA_STATE_DIR would
    // otherwise be treated as the runtime dir).
    let loader_caps_dir = state_dir.path().join("loader-capabilities");
    let map = load_capability_map(&seed_cfg, verifier.as_ref(), &loader_caps_dir)
        .expect("minted seed must load");

    // ALLOW: selecting the default action returns the minted entry, and its
    // raw token round-trips through the Authority's public key.
    let entry = map
        .select(
            "live-session",
            firma_run::capability::issue::DEFAULT_REQUESTED_ACTIONS[0],
            "wttr.in/Berlin",
        )
        .expect("minted entry must select (ALLOW)");
    let claims = verifier
        .verify(&entry.raw_token)
        .expect("minted token must verify against the live Authority public key");
    assert_eq!(claims.agent_id.to_string(), "live-agent");
    assert_eq!(claims.session_id.to_string(), "live-session");
    assert_eq!(
        claims.action_set,
        vec![firma_run::capability::issue::DEFAULT_REQUESTED_ACTIONS[0].to_string()]
    );
}

/// Fake prompt that must never be reached on the remote authority path.
struct UnreachablePrompt;

impl firma_run::authority::AuthorityPromptIo for UnreachablePrompt {
    fn is_tty(&self) -> bool {
        false
    }

    fn confirm(&mut self, _prompt: &str) -> std::io::Result<bool> {
        panic!("prompt must not be invoked for a remote --authority URL");
    }
}

/// Test B: `--no-autostart` against an unreachable Authority fails loudly.
///
/// Drives `resolve_authority` directly (see module docs for why the full CLI
/// cannot reach this path on non-structural-backend hosts). The remote URL
/// points at a closed loopback port, so the `AuthoritySelection::Remote`
/// branch's `probe_authority_url` must yield `RunError::AuthorityUnreachable`.
#[test]
fn no_autostart_unreachable_authority_fails_loudly() {
    let state_dir = tempfile::tempdir().unwrap();
    let runtime_dir = state_dir.path();

    let port = pick_free_port();
    let url = format!("http://127.0.0.1:{port}");

    let identity = firma_run::identity::RunIdentity::new("no-autostart-agent");
    let flags = firma_run::routing::AutostartFlags {
        no_autostart: true,
        ..Default::default()
    };
    let cli = firma_run::authority::AuthorityCli::Remote(url.clone());
    let firma_exe = firma_bin();
    let mut prompt = UnreachablePrompt;

    let result = firma_run::routing::resolve_authority(
        &identity,
        runtime_dir,
        &flags,
        &cli,
        "developer",
        None,
        None,
        &firma_exe,
        &mut prompt,
    );

    let Err(error) = result else {
        panic!("unreachable remote authority must fail");
    };
    assert!(
        matches!(
            error,
            firma_run::error::RunError::AuthorityUnreachable { .. }
        ),
        "expected AuthorityUnreachable, got: {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains("authority unreachable at"),
        "Display must mention the unreachable authority; got: {rendered}"
    );
    assert!(
        rendered.contains(&url),
        "Display must include the offending URL; got: {rendered}"
    );

    // No fallback occurred: no capability seed file was created anywhere under
    // the pinned runtime dir.
    let caps_dir = firma_stack::runtime_paths::capabilities_dir_from(runtime_dir);
    assert!(
        !has_any_file(&caps_dir),
        "no capability file should be created on the failed-authority path"
    );
}

/// Whether `dir` exists and contains at least one entry.
fn has_any_file(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}
