//! A Sidecar authenticating as one run with its runtime credential.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::assert_matches;

use firma_config_schema::sidecar::authority::SidecarCredentials as SchemaSidecarCredentials;
use firma_sidecar::authority_credentials::{
    CredentialSource, SidecarCredential, SidecarCredentialsConfig, SidecarCredentialsConfigError,
};

const VERSION_METADATA: &str = "firma-agent-flow-version";
const RUN_ID: &str = "run_01j0000000e008000000000001";

fn schema(
    pre_shared_key_env: Option<&str>,
    runtime_credential_env: Option<&str>,
    run_id: Option<&str>,
) -> SchemaSidecarCredentials {
    SchemaSidecarCredentials {
        workspace_id: "ws".to_string(),
        sidecar_id: "sc".to_string(),
        pre_shared_key_env: pre_shared_key_env.map(str::to_string),
        pre_shared_key_path: None,
        run_id: run_id.map(str::to_string),
        runtime_credential_env: runtime_credential_env.map(str::to_string),
    }
}

fn runtime_config() -> SidecarCredentialsConfig {
    SidecarCredentialsConfig::try_from(schema(None, Some("FIRMA_RUNTIME_CREDENTIAL"), Some(RUN_ID)))
        .unwrap()
}

#[test]
fn a_runtime_credential_names_its_run() {
    let error =
        SidecarCredentialsConfig::try_from(schema(None, Some("FIRMA_RUNTIME_CREDENTIAL"), None))
            .unwrap_err();
    assert_matches!(
        error,
        SidecarCredentialsConfigError::RuntimeCredentialAndRunMismatch
    );
    insta::assert_snapshot!(
        error.to_string(),
        @"runtime_credential_env and run_id must be set together"
    );
}

#[test]
fn a_runtime_credential_excludes_a_pre_shared_key() {
    let error = SidecarCredentialsConfig::try_from(schema(
        Some("FIRMA_PSK"),
        Some("FIRMA_RUNTIME_CREDENTIAL"),
        Some(RUN_ID),
    ))
    .unwrap_err();
    assert_matches!(
        error,
        SidecarCredentialsConfigError::MultipleCredentialSources
    );
}

#[test]
fn a_sidecar_serves_a_run_only_with_a_runtime_credential() {
    assert!(runtime_config().uses_runtime_credential());
    let pre_shared =
        SidecarCredentialsConfig::try_from(schema(Some("FIRMA_PSK"), None, None)).unwrap();
    assert!(!pre_shared.uses_runtime_credential());
}

#[test]
fn a_runtime_credential_travels_as_a_versioned_bearer_and_never_in_the_body() {
    let credential = runtime_config().runtime_credential("abc").unwrap();

    let request = SidecarCredential::authenticated(Some(&credential), ());
    let authorization = request.metadata().get("authorization").unwrap();
    assert_eq!(authorization.to_str().unwrap(), "Bearer abc");
    assert!(
        authorization.is_sensitive(),
        "HPACK must not index the bearer"
    );
    assert_eq!(
        request
            .metadata()
            .get(VERSION_METADATA)
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );
    assert!(credential.body_credentials().is_none());
    assert_eq!(credential.runtime_bearer(), Some("abc"));
    assert_eq!(credential.run_id(), Some(&RUN_ID.parse().unwrap()));
    let debug = format!("{credential:?}");
    assert!(!debug.contains("abc"), "{debug}");
    assert!(!format!("{request:?}").contains("abc"));
}

#[test]
fn a_pre_shared_key_stays_in_the_body_without_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("psk");
    std::fs::write(&path, "secret").unwrap();
    let config = SidecarCredentialsConfig {
        workspace_id: "ws".to_string(),
        sidecar_id: "sc".to_string(),
        source: CredentialSource::PreSharedKeyFile(path),
    };
    let credential = config.resolve().unwrap();

    let request = SidecarCredential::authenticated(Some(&credential), ());
    assert!(request.metadata().get("authorization").is_none());
    assert!(request.metadata().get(VERSION_METADATA).is_none());
    let body = credential.body_credentials().unwrap();
    assert_eq!(
        (body.workspace_id.as_str(), body.sidecar_id.as_str()),
        ("ws", "sc")
    );
    assert_eq!(body.pre_shared_key, "secret");
    assert!(credential.runtime_bearer().is_none());
    assert!(credential.run_id().is_none());
    assert!(
        SidecarCredential::authenticated(None, ())
            .metadata()
            .is_empty()
    );
}

#[test]
fn a_runtime_credential_value_is_trimmed_and_must_fit_a_header() {
    let config = runtime_config();
    assert_eq!(
        config
            .runtime_credential(" abc\n")
            .unwrap()
            .runtime_bearer(),
        Some("abc")
    );
    for (value, refusal) in [
        (" \n", "runtime credential is empty"),
        ("ab\ncd", "runtime credential is not a valid bearer"),
    ] {
        assert_eq!(config.runtime_credential(value).unwrap_err(), refusal);
    }
}
