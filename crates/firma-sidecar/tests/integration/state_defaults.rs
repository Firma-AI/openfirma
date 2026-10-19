//! Artifact paths the Sidecar resolves when `firma.toml` names none.
//!
//! Each default is the position `firma config` writes into the config file, so
//! a scaffolded deployment and a path-free one must land on the same files.

#![allow(clippy::expect_used, reason = "test code")]

use std::time::Duration;

use firma_config_schema::sidecar::audit::{AuditConfig as SchemaAuditConfig, AuditSink};
use firma_runtime_state::RuntimeLayout;
use firma_sidecar::config::{SidecarConfig, SidecarConfigError};
use firma_sidecar::startup::audit::{load_audit_event_builder, spawn_audit_sink};

/// Generate a fresh P-256 signing key as PKCS#8 PEM at test time, so no real
/// PEM block lives in the source tree.
fn audit_key_pem() -> String {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};

    SigningKey::random(&mut OsRng)
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode signing key as pkcs8 pem")
        .to_string()
}

/// Resolve a schema against `state`, with `mutate` standing in for the parts
/// of `firma.toml` a case cares about.
fn resolve(
    state: &RuntimeLayout,
    mutate: impl FnOnce(&mut firma_config_schema::sidecar::SidecarConfig),
) -> Result<SidecarConfig, SidecarConfigError> {
    let mut schema = firma_config_schema::sidecar::SidecarConfig::default();
    schema.authority.url = Some("http://127.0.0.1:50051".to_string());
    mutate(&mut schema);
    SidecarConfig::resolve(schema, state)
}

/// The shape a path-free `firma.toml` produces: a file sink with neither the
/// log nor the signing key pinned.
fn unpinned_file_sink(state: &RuntimeLayout) -> SidecarConfig {
    resolve(state, |schema| {
        schema.audit = SchemaAuditConfig {
            sink: AuditSink::File,
            file_path: None,
            signing_key_path: None,
            ..SchemaAuditConfig::default()
        };
    })
    .expect("an unpinned file sink is valid")
}

#[test]
fn an_unset_audit_file_path_resolves_to_the_state_audit_log() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let config = unpinned_file_sink(&state);

    assert_eq!(config.audit_file_path(), Some(state.audit_log().as_path()));
}

/// Regression: the sink used to open its log inside the spawned task, whose
/// result `firma sidecar` never joins. A state directory that did not exist
/// yet therefore produced a Sidecar that reported ready and audited nothing.
#[tokio::test]
async fn a_defaulted_audit_log_is_opened_before_the_state_dir_exists() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path().join("not-created-yet"));
    let config = unpinned_file_sink(&state);
    // The key has to be readable for the builder, but the state directory the
    // log defaults into must not exist when the sink is spawned.
    std::fs::create_dir_all(state.root()).expect("create state root");
    std::fs::write(state.audit_key(), audit_key_pem()).expect("write audit key");
    let builder = load_audit_event_builder(&config.audit).expect("the key is readable");
    std::fs::remove_dir_all(state.root()).expect("remove the state root again");

    let (_payload_tx, payload_rx) = tokio::sync::mpsc::channel(1);
    let exit = tokio_util::sync::CancellationToken::new();
    let handle =
        spawn_audit_sink(&config, payload_rx, builder, exit.clone()).expect("spawn the audit sink");

    // No polling: the log is opened before the sink is spawned, so it is there
    // the moment the call returns.
    assert!(
        state.audit_log().is_file(),
        "the audit log must exist once the sink is spawned"
    );
    exit.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("the sink shuts down promptly")
        .expect("sink task joins")
        .expect("sink exits cleanly");
}

/// A log that cannot be opened must fail the spawn rather than resolve in a
/// task nobody joins.
#[tokio::test]
async fn an_unopenable_audit_log_fails_the_spawn() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    std::fs::write(state.audit_key(), audit_key_pem()).expect("write audit key");
    // A regular file where the log's parent directory would go: the sink
    // creates missing parents, so only a non-directory can block it.
    let blocked = temp.path().join("blocked");
    std::fs::write(&blocked, "").expect("write the blocking file");
    let config = resolve(&state, |schema| {
        schema.audit = SchemaAuditConfig {
            sink: AuditSink::File,
            file_path: Some(blocked.join("audit.jsonl")),
            ..SchemaAuditConfig::default()
        };
    })
    .expect("a pinned log path is valid");
    let builder = load_audit_event_builder(&config.audit).expect("the key is readable");
    let (_payload_tx, payload_rx) = tokio::sync::mpsc::channel(1);

    let error = spawn_audit_sink(
        &config,
        payload_rx,
        builder,
        tokio_util::sync::CancellationToken::new(),
    )
    .expect_err("an unopenable log must fail startup");

    assert!(
        error.to_string().contains(&blocked.display().to_string()),
        "the error must name the log that could not be opened: {error}"
    );
}

/// The key is defaulted rather than written by the operator, so a bare ENOENT
/// reads as a bug. Name the command that generates it instead.
#[test]
fn a_missing_signing_key_names_the_default_path_and_the_remedy() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    let config = unpinned_file_sink(&state);

    let error =
        load_audit_event_builder(&config.audit).expect_err("a missing signing key must fail");

    let message = error.to_string();
    assert!(
        message.starts_with(&format!(
            "failed to read signing key from {}",
            state.audit_key().display()
        )),
        "error did not name the defaulted key path: {message}"
    );
    assert!(
        message.ends_with("run `firma config` to generate it, or set signing_key_path"),
        "error did not name the remedy: {message}"
    );
}

/// A path the operator chose gets no `firma config` remedy: that command would
/// generate a different file than the one they named.
#[test]
fn a_missing_pinned_signing_key_is_reported_without_the_remedy() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    let pinned = temp.path().join("pinned-audit.key");
    let config = resolve(&state, |schema| {
        schema.audit.signing_key_path = Some(pinned.clone());
    })
    .expect("a pinned signing key is valid");

    let error =
        load_audit_event_builder(&config.audit).expect_err("a missing signing key must fail");

    let message = error.to_string();
    assert!(
        message.contains(&pinned.display().to_string()),
        "error did not name the pinned key path: {message}"
    );
    assert!(
        !message.contains("firma config"),
        "a pinned path must not be blamed on scaffolding: {message}"
    );
}

#[test]
fn an_unset_ca_dir_resolves_to_the_state_generated_ca() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let config = resolve(&state, |_| {}).expect("an empty configuration is valid");

    assert_eq!(config.ca_dir(), state.generated_ca_dir());
}

#[test]
fn an_explicit_ca_dir_wins_over_the_state_dir_default() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    let pinned = temp.path().join("pinned-ca");

    let config = resolve(&state, |schema| {
        schema.ca.dir = Some(pinned.clone());
    })
    .expect("a pinned CA directory is valid");

    assert_eq!(config.ca_dir(), pinned);
}

/// The trust anchors are adopted only when the material is there: a deployment
/// that never generated them keeps its reject-all token verifier rather than
/// failing on a file nobody wrote.
#[test]
fn authority_trust_anchors_are_adopted_only_when_the_material_exists() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let absent = resolve(&state, |_| {}).expect("config without anchors is valid");
    assert_eq!(absent.authority_public_key_path(), None);
    assert_eq!(absent.authority_ca_cert_path(), None);

    std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
    std::fs::write(state.authority_public_key(), "pub").expect("write public key");
    std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");

    let present = resolve(&state, |_| {}).expect("config with adopted anchors is valid");
    assert_eq!(
        present.authority_public_key_path(),
        Some(state.authority_public_key().as_path())
    );
    assert_eq!(
        present.authority_ca_cert_path(),
        Some(state.authority_tls_ca_certificate().as_path())
    );
}

/// An `https://` Authority is still rejected without a CA certificate, but the
/// diagnostic has to name the path that was looked for: now that the anchor is
/// adopted from the state directory, "set `authority.ca_cert_path`" alone does
/// not say where the Sidecar expected to find one.
#[test]
fn an_https_authority_without_a_ca_names_the_state_dir_default() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let error = resolve(&state, |schema| {
        schema.authority.url = Some("https://authority.test:9443".to_string());
    })
    .expect_err("an https Authority without a CA certificate must be rejected");

    assert!(
        matches!(
            &error,
            SidecarConfigError::MissingCaCertForHttps { state_default }
                if state_default == &state.authority_tls_ca_certificate()
        ),
        "unexpected error: {error}"
    );
    assert!(
        error
            .to_string()
            .contains(&state.authority_tls_ca_certificate().display().to_string()),
        "the diagnostic must name the state-directory default: {error}"
    );
}

/// The adopted anchor is what makes an `https://` Authority valid, so every
/// consumer that validates this config — `firma doctor` included — has to
/// resolve the same state directory.
#[test]
fn an_https_authority_is_accepted_when_the_state_dir_holds_the_ca() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
    std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");

    let config = resolve(&state, |schema| {
        schema.authority.url = Some("https://authority.test:9443".to_string());
    })
    .expect("the adopted CA certificate satisfies the https requirement");

    assert_eq!(
        config.authority_ca_cert_path(),
        Some(state.authority_tls_ca_certificate().as_path())
    );
}
