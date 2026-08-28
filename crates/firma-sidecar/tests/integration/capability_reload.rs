//! Integration coverage for the Stage 1 capability seed hot-reload watcher
//! ([`firma_sidecar::startup::capability::CapabilityReloader`]).
//!
//! Exercises the real file watcher + async reload loop: a re-minted seed is
//! hot-swapped into the live `CapabilityMap`, while a removed or invalid seed
//! leaves the previous map in place (fail-closed on the token's own expiry).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};
use firma_core::token::paseto::{PasetoV4Signer, PasetoV4Verifier};
use firma_core::{CapabilityClaims, CapabilitySeed, TokenSigner, TokenVerifier};
use firma_identifiers::TokenId;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::fmt::MakeWriter;

use firma_sidecar::config::CapabilitySeedConfig;
use firma_sidecar::enforcement::capability_validation::CapabilityMapHandle;
use firma_sidecar::startup::capability::{CapabilityReloader, load_capability_map};

const SESSION: &str = "sess_reload";
const ACTION: &str = "communication.external.send";
const RESOURCE: &str = "wttr.in";

#[derive(Clone, Default)]
struct CapturingWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl CapturingWriter {
    fn snapshot(&self) -> String {
        let guard: MutexGuard<'_, Vec<u8>> =
            self.buffer.lock().expect("capture lock must be available");
        String::from_utf8_lossy(&guard).into_owned()
    }
}

impl Write for CapturingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut guard = self.buffer.lock().expect("capture lock must be available");
        guard.extend_from_slice(data);
        drop(guard);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

struct Keys {
    signer: PasetoV4Signer,
    public: Vec<u8>,
}

fn keys() -> Keys {
    let kp = AsymmetricKeyPair::<V4>::generate().expect("keypair");
    Keys {
        signer: PasetoV4Signer::try_new(kp.secret.as_bytes()).expect("signer"),
        public: kp.public.as_bytes().to_vec(),
    }
}

fn verifier(public: &[u8]) -> Arc<dyn TokenVerifier + Send + Sync> {
    Arc::new(PasetoV4Verifier::try_new(public).expect("verifier"))
}

fn claims(expiry: DateTime<Utc>) -> CapabilityClaims {
    let now = Utc::now();
    CapabilityClaims {
        token_id: TokenId::generate(),
        agent_id: "agt_01j0000000e008000000000001".parse().expect("agent id"),
        session_id: SESSION.parse().expect("session id"),
        action_set: vec![ACTION.to_string()],
        resource_scope: "*".to_string(),
        issued_at: now,
        expiry,
        context_hash: "deadbeef".to_string(),
    }
}

/// Sign fresh claims and return the seed plus the raw token it carries.
fn signed_seed(signer: &PasetoV4Signer) -> (CapabilitySeed, String) {
    let claims = claims(Utc::now() + chrono::Duration::minutes(15));
    let raw_token = signer.sign(&claims).expect("sign");
    (
        CapabilitySeed::from_claims(&claims, raw_token.clone()),
        raw_token,
    )
}

/// Atomically write `seed` to `target` (temp file + rename in the same dir),
/// mirroring how `firma run` re-mints the seed.
fn write_seed(dir: &Path, target: &Path, seed: &CapabilitySeed) {
    let body = toml::to_string(seed).expect("serialize seed");
    let tmp = dir.join("seed.tmp");
    std::fs::write(&tmp, body).expect("write temp seed");
    std::fs::rename(&tmp, target).expect("rename seed into place");
}

fn runtime_seed(root: &Path) -> (firma_runtime_state::RuntimeLayout, PathBuf) {
    let runtime_layout = firma_runtime_state::RuntimeLayout::from_root(root);
    let capabilities_dir = runtime_layout.capabilities_dir();
    std::fs::create_dir(&capabilities_dir).expect("create runtime capabilities directory");
    let seed_path = capabilities_dir.join("seed.toml");
    (runtime_layout, seed_path)
}

fn handle_from(
    seed_config: &CapabilitySeedConfig,
    verifier: &Arc<dyn TokenVerifier + Send + Sync>,
    capabilities_dir: &Path,
) -> CapabilityMapHandle {
    let map =
        load_capability_map(seed_config, verifier.as_ref(), capabilities_dir).expect("initial map");
    CapabilityMapHandle::new(map)
}

fn selected_raw_token(handle: &CapabilityMapHandle) -> Option<String> {
    handle
        .load()
        .select(SESSION, ACTION, RESOURCE)
        .ok()
        .map(|entry| entry.raw_token.clone())
}

/// Poll the live map until `select` resolves to `expected` (or time out).
async fn wait_for_token(handle: &CapabilityMapHandle, expected: &str) -> bool {
    for _ in 0..100 {
        if selected_raw_token(handle).as_deref() == Some(expected) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn wait_for_log(writer: &CapturingWriter, expected: &str) -> String {
    for _ in 0..100 {
        let logs = writer.snapshot();
        if logs.contains(expected) {
            return logs;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    writer.snapshot()
}

fn assert_initial_load_and_watcher_reject_escape(
    runtime_layout: &firma_runtime_state::RuntimeLayout,
    configured_path: &Path,
    resolved_external_path: &Path,
    verifier: Arc<dyn TokenVerifier + Send + Sync>,
) {
    let capabilities_dir = runtime_layout.capabilities_dir();
    let resolved_capabilities_dir =
        std::fs::canonicalize(&capabilities_dir).expect("canonical capabilities directory");
    let config = CapabilitySeedConfig {
        paths: vec![configured_path.to_path_buf()],
        hot_reload: true,
    };
    let resolved_external_path =
        std::fs::canonicalize(resolved_external_path).expect("canonical external seed");

    let initial_error = load_capability_map(&config, verifier.as_ref(), &capabilities_dir)
        .expect_err("initial load must reject a seed resolving outside the runtime directory");
    let empty_map = load_capability_map(
        &CapabilitySeedConfig::default(),
        verifier.as_ref(),
        &capabilities_dir,
    )
    .expect("empty capability map");
    let Err(watcher_error) = CapabilityReloader::spawn(
        runtime_layout,
        &config,
        verifier,
        CapabilityMapHandle::new(empty_map),
        CancellationToken::new(),
    ) else {
        panic!("watcher setup must reject a seed resolving outside the runtime directory");
    };

    for error in [initial_error, watcher_error] {
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(configured_path.to_string_lossy().as_ref()),
            "error must identify the configured path; got: {rendered}"
        );
        assert!(
            rendered.contains(resolved_external_path.to_string_lossy().as_ref()),
            "error must identify the resolved external path; got: {rendered}"
        );
        assert!(
            rendered.contains(resolved_capabilities_dir.to_string_lossy().as_ref()),
            "error must identify the canonical capabilities directory; got: {rendered}"
        );
        assert!(
            rendered.contains("must be under the runtime capabilities directory"),
            "error must identify the containment boundary; got: {rendered}"
        );
    }
}

#[tokio::test]
async fn traversal_cannot_escape_initial_load_or_watcher_boundary() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, _seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();
    let external_path = dir.path().join("external-seed.toml");
    let configured_path = capabilities_dir.join("..").join("external-seed.toml");
    std::fs::write(&external_path, "outside = 'runtime boundary'").expect("write external seed");

    assert_initial_load_and_watcher_reject_escape(
        &runtime_layout,
        &configured_path,
        &external_path,
        verifier(&keys.public),
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unix_symlink_cannot_escape_initial_load_or_watcher_boundary() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, _seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();
    let external_path = dir.path().join("external-seed.toml");
    let configured_path = capabilities_dir.join("linked-seed.toml");
    std::fs::write(&external_path, "outside = 'runtime boundary'").expect("write external seed");
    std::os::unix::fs::symlink(&external_path, &configured_path).expect("create seed symlink");

    assert_initial_load_and_watcher_reject_escape(
        &runtime_layout,
        &configured_path,
        &external_path,
        verifier(&keys.public),
    );
}

#[cfg(windows)]
#[tokio::test]
async fn windows_symlink_cannot_escape_initial_load_or_watcher_boundary() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, _seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();
    let external_path = dir.path().join("external-seed.toml");
    let configured_path = capabilities_dir.join("linked-seed.toml");
    std::fs::write(&external_path, "outside = 'runtime boundary'").expect("write external seed");
    std::os::windows::fs::symlink_file(&external_path, &configured_path)
        .expect("create seed symlink");

    assert_initial_load_and_watcher_reject_escape(
        &runtime_layout,
        &configured_path,
        &external_path,
        verifier(&keys.public),
    );
}

#[test]
fn startup_parse_error_omits_seed_material() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, seed_path) = runtime_seed(dir.path());
    let (seed, raw_token) = signed_seed(&keys.signer);
    let secret = "startup-secret-value";
    let body = format!(
        "{}unknown = \"{secret}\"\n",
        toml::to_string(&seed).expect("serialize seed")
    );
    std::fs::write(&seed_path, &body).expect("write noncanonical seed");
    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };

    let error = load_capability_map(
        &seed_config,
        verifier(&keys.public).as_ref(),
        &runtime_layout.capabilities_dir(),
    )
    .expect_err("unknown field must fail startup parsing")
    .to_string();

    assert!(error.contains(&seed_path.display().to_string()));
    assert!(error.contains("is not canonical CapabilitySeed TOML"));
    assert!(
        !error.contains(&raw_token),
        "error exposed raw token: {error}"
    );
    assert!(
        !error.contains(secret),
        "error exposed unknown value: {error}"
    );
    assert!(
        !error.contains(&body),
        "error exposed seed document: {error}"
    );
}

#[tokio::test]
async fn reload_hot_swaps_map_on_seed_rewrite() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();

    let (seed_v1, raw_v1) = signed_seed(&keys.signer);
    write_seed(&capabilities_dir, &seed_path, &seed_v1);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, &capabilities_dir);
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_v1.as_str())
    );

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &runtime_layout,
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    // Re-mint: a distinct token for the same selection key.
    let (seed_v2, raw_v2) = signed_seed(&keys.signer);
    assert_ne!(raw_v1, raw_v2, "re-mint must produce a distinct token");
    write_seed(&capabilities_dir, &seed_path, &seed_v2);

    assert!(
        wait_for_token(&handle, &raw_v2).await,
        "map should hot-swap to the re-minted token"
    );

    cancel.cancel();
}

#[tokio::test]
async fn reload_keeps_previous_map_when_seed_removed() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();

    let (seed_v1, raw_v1) = signed_seed(&keys.signer);
    write_seed(&capabilities_dir, &seed_path, &seed_v1);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, &capabilities_dir);

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &runtime_layout,
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    // Teardown deletes the seed; the watcher must keep the previous map rather
    // than swapping in an empty one.
    std::fs::remove_file(&seed_path).expect("remove seed");

    // Give the watcher time to observe and process the Remove event.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_v1.as_str()),
        "removing the seed must not drop the live capability map"
    );

    cancel.cancel();
}

#[tokio::test]
async fn reload_keeps_previous_map_on_invalid_seed() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();

    let (seed_v1, raw_v1) = signed_seed(&keys.signer);
    write_seed(&capabilities_dir, &seed_path, &seed_v1);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, &capabilities_dir);

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &runtime_layout,
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    // A rewrite whose mirror parses but whose raw_token fails verification must
    // not be installed; the previous valid map is retained.
    let mut tampered = seed_v1.clone();
    tampered.raw_token = "v4.public.not-a-valid-token".to_string();
    write_seed(&capabilities_dir, &seed_path, &tampered);

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_v1.as_str()),
        "an unverifiable re-mint must not replace the live map"
    );

    cancel.cancel();
}

#[tokio::test]
async fn reload_parse_error_is_secret_safe_and_keeps_previous_map() {
    let keys = keys();
    let dir = tempfile::tempdir().expect("tempdir");
    let (runtime_layout, seed_path) = runtime_seed(dir.path());
    let capabilities_dir = runtime_layout.capabilities_dir();
    let (seed, raw_token) = signed_seed(&keys.signer);
    write_seed(&capabilities_dir, &seed_path, &seed);

    let seed_config = CapabilitySeedConfig {
        paths: vec![seed_path.clone()],
        hot_reload: true,
    };
    let verifier = verifier(&keys.public);
    let handle = handle_from(&seed_config, &verifier, &capabilities_dir);
    let writer = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer({
            let writer = writer.clone();
            move || writer.clone()
        })
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    let cancel = CancellationToken::new();
    let _reloader = CapabilityReloader::spawn(
        &runtime_layout,
        &seed_config,
        Arc::clone(&verifier),
        handle.clone(),
        cancel.clone(),
    )
    .expect("spawn reloader");

    let secret = "reload-secret-value";
    let body = format!(
        "{}unknown = \"{secret}\"\n",
        toml::to_string(&seed).expect("serialize seed")
    );
    let temporary = capabilities_dir.join("seed.invalid.tmp");
    std::fs::write(&temporary, &body).expect("write invalid seed");
    std::fs::rename(&temporary, &seed_path).expect("replace seed");

    let logs = wait_for_log(&writer, "capability seed reload failed").await;
    assert!(
        logs.contains(&seed_path.display().to_string()),
        "reload log omitted seed path: {logs}"
    );
    assert!(
        logs.contains("is not canonical CapabilitySeed TOML"),
        "got: {logs}"
    );
    assert!(!logs.contains(&raw_token), "log exposed raw token: {logs}");
    assert!(!logs.contains(secret), "log exposed unknown value: {logs}");
    assert!(!logs.contains(&body), "log exposed seed document: {logs}");
    assert_eq!(
        selected_raw_token(&handle).as_deref(),
        Some(raw_token.as_str()),
        "a structurally invalid reload must retain the previous map"
    );

    cancel.cancel();
}
