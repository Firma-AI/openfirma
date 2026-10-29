//! Artifact paths the Sidecar resolves when `firma.toml` names none.
//!
//! Each default is the position `firma config` writes into the config file, so
//! a scaffolded deployment and a path-free one must land on the same files.

#![allow(clippy::expect_used, reason = "test code")]

use std::assert_matches;
use std::time::Duration;

use firma_config_schema::sidecar::audit::{AuditConfig as SchemaAuditConfig, AuditSink};
use firma_runtime_state::RuntimeLayout;
use firma_sidecar::authority_tls::AuthorityTls;
use firma_sidecar::config::{
    AuthorityConfigError, AuthorityTrust, AuthorityTrustError, SidecarConfig, SidecarConfigError,
    default_authority_ca,
};
use firma_sidecar::startup::audit::{load_audit_event_builder, spawn_audit_sink};

/// Generate a fresh P-256 signing key as PKCS#8 PEM at test time, so no real
/// PEM block lives in the source tree.
fn audit_key_pem() -> String {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};

    SigningKey::generate()
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode signing key as pkcs8 pem")
        .to_string()
}

#[test]
fn runtime_run_identifiers_are_validated_before_credential_resolution() {
    use firma_config_schema::sidecar::authority::SidecarCredentials;
    use firma_sidecar::authority_credentials::{
        CredentialSource, SidecarCredentialsConfig, SidecarCredentialsConfigError,
    };

    let mut schema = SidecarCredentials {
        workspace_id: "workspace".into(),
        sidecar_id: "sidecar".into(),
        pre_shared_key_env: None,
        pre_shared_key_path: None,
        runtime_credential_env: Some("CARGO_PKG_NAME".into()),
        run_id: None,
    };
    for invalid in ["not-a-run", "ses_01j0000000e008000000000001"] {
        schema.run_id = Some(invalid.into());
        let error = SidecarCredentialsConfig::try_from(schema.clone()).expect_err("invalid run");
        assert_eq!(error, SidecarCredentialsConfigError::InvalidRunId);
        insta::allow_duplicates! {
            insta::assert_snapshot!(error.to_string(), @"run_id must be a valid RunId");
        }
    }

    let run = "run_01j0000000e008000000000001";
    schema.run_id = Some(run.into());
    let config = SidecarCredentialsConfig::try_from(schema).expect("canonical run");
    assert_eq!(
        config.source,
        CredentialSource::Runtime {
            run_id: run.parse().expect("canonical run"),
            env: "CARGO_PKG_NAME".into(),
        }
    );
    let credential = config
        .resolve()
        .expect("cargo supplies the credential variable");
    let request = firma_sidecar::authority_credentials::SidecarCredential::authenticated(
        Some(&credential),
        (),
    );
    assert_eq!(
        request.metadata().get("authorization").expect("bearer"),
        concat!("Bearer ", env!("CARGO_PKG_NAME"))
    );
    assert!(credential.body_credentials().is_none());
    assert!(!format!("{credential:?}").contains(concat!("Bearer ", env!("CARGO_PKG_NAME"))));
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
    let handle = spawn_audit_sink(
        &config,
        &AuthorityTls::read(&config.authority).expect("authority TLS"),
        payload_rx,
        builder,
        exit.clone(),
    )
    .expect("spawn the audit sink");

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
        &AuthorityTls::read(&config.authority).expect("authority TLS"),
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
    assert_eq!(absent.authority_trust(), &AuthorityTrust::PlatformStore);

    std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
    std::fs::write(state.authority_public_key(), "pub").expect("write public key");
    std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");

    let present = resolve(&state, |_| {}).expect("config with adopted anchors is valid");
    assert_eq!(
        present.authority_public_key_path(),
        Some(state.authority_public_key().as_path())
    );
    assert_eq!(
        present.authority_trust(),
        &AuthorityTrust::CustomCas(vec![state.authority_tls_ca_certificate()])
    );
}

/// Named CAs are the whole trust, in order, and keep the state-dir CA from
/// being adopted even for an Authority on this host.
#[test]
fn named_cas_are_trusted_in_order_and_block_the_state_dir_adoption() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
    std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");

    let named = resolve(&state, |schema| {
        schema.authority.url = Some("https://127.0.0.1:9443".to_string());
        schema.authority.ca_cert_paths = vec!["b.pem".into(), "a.pem".into()];
    })
    .expect("a named CA satisfies the loopback rule");
    assert_eq!(
        named.authority_trust(),
        &AuthorityTrust::CustomCas(vec!["b.pem".into(), "a.pem".into()]),
        "the named CAs must keep the state-dir CA out"
    );
}

/// With the platform roots disabled, a named CA is the only trust left:
/// none at all is rejected, before the loopback rule could name the state-dir
/// default instead, and for a plaintext URL, where no other rule applies.
#[test]
fn disabled_platform_roots_require_a_named_ca() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let error = resolve(&state, |schema| {
        schema.authority.url = Some("https://127.0.0.1:9443".to_string());
        schema.authority.disable_platform_roots = true;
    })
    .expect_err("no trust source at all must be rejected");
    assert_matches!(
        error,
        SidecarConfigError::Authority(AuthorityConfigError::Trust(
            AuthorityTrustError::NoTrustAnchors
        ))
    );
    insta::assert_snapshot!(error.to_string(), @"authority: authority.disable_platform_roots = true requires authority.ca_cert_paths");

    let plaintext = resolve(&state, |schema| {
        schema.authority.disable_platform_roots = true;
    })
    .expect_err("the switch applies to a plaintext URL too");
    assert_matches!(
        plaintext,
        SidecarConfigError::Authority(AuthorityConfigError::Trust(
            AuthorityTrustError::NoTrustAnchors
        ))
    );

    let pinned = resolve(&state, |schema| {
        schema.authority.url = Some("https://authority.example:443".to_string());
        schema.authority.disable_platform_roots = true;
        schema.authority.ca_cert_paths = vec!["corp.pem".into()];
    })
    .expect("a named CA is a complete trust source");
    assert_eq!(
        pinned.authority_trust(),
        &AuthorityTrust::CustomCas(vec!["corp.pem".into()])
    );
}

/// A blank list entry would name no file at all, so it is refused.
#[test]
fn a_blank_ca_list_entry_is_rejected() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let error = resolve(&state, |schema| {
        schema.authority.ca_cert_paths = vec!["a.pem".into(), String::new().into()];
    })
    .expect_err("a blank list entry must be rejected");

    assert_matches!(
        error,
        SidecarConfigError::Authority(AuthorityConfigError::Trust(
            AuthorityTrustError::EmptyCaCertPath
        ))
    );
    insta::assert_snapshot!(error.to_string(), @"authority: authority.ca_cert_paths entries must not be empty");
}

/// An `https://` Authority on this host is still rejected without a CA
/// certificate, since no public CA certifies a loopback name; the
/// diagnostic has to name the path that was looked for: now that the anchor is
/// adopted from the state directory, "set `authority.ca_cert_paths`" alone does
/// not say where the Sidecar expected to find one.
#[test]
fn an_https_authority_without_a_ca_names_the_state_dir_default() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());

    let error = resolve(&state, |schema| {
        schema.authority.url = Some("https://127.0.0.1:9443".to_string());
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

/// A local Authority's CA is adopted from the state directory, so every
/// consumer that validates this config — `firma doctor` included — has to
/// resolve the same state directory.
#[test]
fn a_local_https_authority_adopts_the_state_dir_ca() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
    std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");

    let config = resolve(&state, |schema| {
        schema.authority.url = Some("https://127.0.0.1:9443".to_string());
    })
    .expect("a local https Authority adopts the CA certificate");

    assert_eq!(
        config.authority_trust(),
        &AuthorityTrust::CustomCas(vec![state.authority_tls_ca_certificate()])
    );
}

/// The state directory's CA belongs to the Authority `firma config` set up on
/// this host. A remote Authority, including one reached through a loopback
/// tunnel, presents its own certificate, so it is verified against the
/// platform's roots instead of that CA.
#[test]
fn the_state_dir_ca_is_the_default_only_for_an_authority_on_this_host() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let state = RuntimeLayout::from_root(temp.path());
    std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
    std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");
    let local = Some(state.authority_tls_ca_certificate());

    for (url, connect_addr, expected) in [
        (None, None, local.clone()),
        (Some("https://LOCALHOST:9443"), None, local.clone()),
        (Some("https://[::1]:9443"), None, local.clone()),
        (
            Some("https://127.0.0.1:9443"),
            Some("[::ffff:127.0.0.1]:9443"),
            local,
        ),
        (Some("https://authority.example:443"), None, None),
        (
            Some("https://authority.example:443"),
            Some("127.0.0.1:9443"),
            None,
        ),
        (
            Some("https://localhost:9443"),
            Some("192.0.2.10:9443"),
            None,
        ),
        (Some("not a url"), None, None),
    ] {
        let connect_addr = connect_addr.map(|address| address.parse().expect("fixture address"));
        assert_eq!(
            default_authority_ca(url, connect_addr, &state),
            expected,
            "url {url:?} through {connect_addr:?}"
        );
    }
}

/// A remote `https://` Authority needs no CA: with none configured it is
/// valid, keeps the platform's roots, and never inherits the local CA. That
/// holds for the routes where only one of the logical host and the physical
/// address is loopback, which both CA adoption and startup validation judge
/// from both; without a state-dir CA only the validation is in play.
#[test]
fn a_remote_https_authority_is_valid_without_a_ca() {
    for state_dir_ca in [true, false] {
        let temp = tempfile::tempdir().expect("temporary directory");
        let state = RuntimeLayout::from_root(temp.path());
        if state_dir_ca {
            std::fs::create_dir_all(state.tls_dir()).expect("create tls dir");
            std::fs::write(state.authority_tls_ca_certificate(), "ca").expect("write ca cert");
        }

        for (url, connect_addr) in [
            ("https://authority.example:443", None),
            ("https://authority.example:443", Some("127.0.0.1:9443")),
            ("https://localhost:9443", Some("192.0.2.10:9443")),
        ] {
            let route = format!("{url} through {connect_addr:?}, state-dir CA {state_dir_ca}");
            let config = resolve(&state, |schema| {
                schema.authority.url = Some(url.to_string());
                schema.authority.connect_addr =
                    connect_addr.map(|address| address.parse().expect("fixture address"));
            })
            .unwrap_or_else(|error| panic!("{route} needs no CA: {error}"));

            assert_eq!(
                config.authority_trust(),
                &AuthorityTrust::PlatformStore,
                "{route}"
            );
        }
    }
}
