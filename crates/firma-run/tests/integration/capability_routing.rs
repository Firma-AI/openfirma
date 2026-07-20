//! Effective-key and managed-capability routing coverage for `firma run`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::backend::{BackendKind, EnforcementProof, NetworkConfinement, SandboxHandle};
use firma_run::config::{CapabilityLeaseConfig, CapabilitySource, NetworkPolicy, SidecarEndpoint};
#[cfg(unix)]
use firma_run::error::RunError;
use firma_run::identity::RunIdentity;
use firma_run::routing::{
    AutostartFlags, ResolveAuthorityRequest, ResolvedAuthority, prepare_network_runtime,
    resolve_authority,
};

struct NoPrompt;

impl AuthorityPromptIo for NoPrompt {
    fn is_tty(&self) -> bool {
        false
    }

    fn confirm(&mut self, _prompt: &str) -> std::io::Result<bool> {
        panic!("prompt must not be called")
    }
}

fn sandbox_handle(identity: &RunIdentity, runtime_dir: &Path) -> SandboxHandle {
    SandboxHandle {
        backend: BackendKind::Vz,
        runtime_dir: runtime_dir.to_path_buf(),
        identity: identity.clone(),
        mounts: Vec::new(),
        network_policy: NetworkPolicy {
            enforce_network_namespace: false,
            fail_closed: true,
        },
    }
}

fn enforcement_proof() -> EnforcementProof {
    EnforcementProof {
        backend: BackendKind::Vz,
        structural: false,
        fail_closed: true,
        detail: "capability routing test".to_string(),
        network_confinement: NetworkConfinement::ProxyOnly,
    }
}

fn authority(public_key_path: Option<PathBuf>) -> ResolvedAuthority {
    ResolvedAuthority {
        url: "http://127.0.0.1:1".to_string(),
        ca_cert_path: None,
        pub_key_path: public_key_path,
        credentials: None,
        credentials_config: None,
        supervisor: None,
    }
}

fn capability(source: CapabilitySource, public_key_path: Option<PathBuf>) -> CapabilityLeaseConfig {
    CapabilityLeaseConfig {
        source,
        public_key_path,
        refresh_ratio: 0.60,
        grace_seconds: 30,
    }
}

fn autostart_flags(capability_seed_path: Option<PathBuf>) -> AutostartFlags {
    AutostartFlags {
        sidecar_autostart: true,
        startup_timeout: Duration::from_millis(100),
        capability_seed_path,
        ..AutostartFlags::default()
    }
}

fn marker_dir(identity: &RunIdentity) -> PathBuf {
    let runtime_dir = firma_runtime_state::runtime_paths::default_runtime_dir();
    firma_runtime_state::runtime_paths::run_entry_from(&runtime_dir, &identity.sandbox_id)
}

#[cfg(unix)]
fn read_synthesized_sidecar(identity: &RunIdentity) -> toml::Value {
    let path = marker_dir(identity).join("sidecar.toml");
    let text = std::fs::read_to_string(path).expect("read synthesized sidecar config");
    toml::from_str(&text).expect("parse synthesized sidecar config")
}

fn remove_marker(identity: &RunIdentity) {
    let _ = std::fs::remove_dir_all(marker_dir(identity));
}

fn resolve_remote_authority(
    config_dir: &Path,
    authority_public_key_path: &Path,
    capability_public_key_path: Option<&Path>,
    working_dir: &Path,
) -> ResolvedAuthority {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind authority probe");
    let authority_addr = listener.local_addr().expect("authority address");
    let config_path = config_dir.join(firma_config_loader::CONFIG_FILE_NAME);
    let authority_public_key_path = authority_public_key_path.display();
    std::fs::write(
        &config_path,
        format!(
            concat!(
                "[sidecar.authority]\n",
                "url = \"http://{authority_addr}\"\n",
                "public_key_path = \"{authority_public_key_path}\"\n",
            ),
            authority_addr = authority_addr,
            authority_public_key_path = authority_public_key_path,
        ),
    )
    .expect("write config");
    let identity = RunIdentity::new("capability-routing");
    let mut prompt = NoPrompt;

    resolve_authority(
        ResolveAuthorityRequest {
            identity: &identity,
            runtime_dir: &config_dir.join("runtime"),
            flags: &AutostartFlags::default(),
            cli: &AuthorityCli::Unset,
            profile_name: "developer",
            user_config_path: Some(&config_path),
            user_config_dir: config_path.parent(),
            firma_exe: &config_dir.join("firma"),
            capability_public_key_path,
            working_dir,
        },
        &mut prompt,
    )
    .expect("resolve remote authority")
}

#[test]
fn relative_capability_key_overrides_authority_key_from_working_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let working_dir = dir.path().join("workspace");
    let resolved = resolve_remote_authority(
        dir.path(),
        Path::new("keys/authority.pub"),
        Some(Path::new("keys/firmateam.pub")),
        &working_dir,
    );

    assert_eq!(
        resolved.pub_key_path,
        Some(working_dir.join("keys/firmateam.pub"))
    );
}

#[test]
fn absolute_capability_key_is_not_rebased() {
    let dir = tempfile::tempdir().expect("tempdir");
    let capability_key = dir.path().join("firmateam.pub");
    let resolved = resolve_remote_authority(
        dir.path(),
        Path::new("keys/authority.pub"),
        Some(&capability_key),
        &dir.path().join("workspace"),
    );

    assert_eq!(resolved.pub_key_path, Some(capability_key));
}

#[test]
fn omitted_capability_key_retains_authority_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let resolved = resolve_remote_authority(
        dir.path(),
        Path::new("keys/authority.pub"),
        None,
        &dir.path().join("workspace"),
    );

    assert_eq!(
        resolved.pub_key_path,
        Some(dir.path().join("keys/authority.pub"))
    );
}

#[test]
fn autostart_with_effective_key_attempts_managed_capability_mint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = RunIdentity::new("managed-capability");
    let missing_key = dir.path().join("missing-firmateam.pub");
    let handle = sandbox_handle(&identity, dir.path());

    let error = prepare_network_runtime(
        &handle,
        &enforcement_proof(),
        &SidecarEndpoint::Tcp {
            addr: "127.0.0.1:1".parse().expect("sidecar address"),
        },
        &identity,
        &autostart_flags(None),
        authority(Some(missing_key.clone())),
        &capability(CapabilitySource::Disabled, Some(missing_key)),
    )
    .err()
    .expect("managed mint must fail on missing key");

    assert!(
        error.to_string().contains("read authority public key"),
        "got: {error}"
    );
    assert!(
        !marker_dir(&identity).join("sidecar.toml").exists(),
        "mint must happen before Sidecar synthesis"
    );
    remove_marker(&identity);
}

#[cfg(unix)]
#[test]
fn capability_file_suppresses_mint_and_reaches_sidecar_synthesis() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = RunIdentity::new("external-capability-file");
    let missing_key = dir.path().join("missing-firmateam.pub");
    let seed_path = dir.path().join("existing-capability.toml");
    std::fs::write(&seed_path, "existing seed\n").expect("write seed placeholder");
    let handle = sandbox_handle(&identity, dir.path());

    let error = prepare_network_runtime(
        &handle,
        &enforcement_proof(),
        &SidecarEndpoint::Tcp {
            addr: "127.0.0.1:1".parse().expect("sidecar address"),
        },
        &identity,
        &autostart_flags(Some(seed_path.clone())),
        authority(Some(missing_key.clone())),
        &capability(
            CapabilitySource::File {
                path: seed_path.clone(),
            },
            Some(missing_key.clone()),
        ),
    )
    .err()
    .expect("test binary cannot autostart as the Sidecar");

    assert!(
        matches!(
            error,
            RunError::SidecarReadyTimeout { .. } | RunError::SidecarStartupFailed { .. }
        ),
        "got: {error}"
    );
    let sidecar = read_synthesized_sidecar(&identity);
    let sidecar_table = sidecar.get("sidecar").expect("sidecar table");
    assert_eq!(
        sidecar_table
            .get("authority")
            .and_then(|authority| authority.get("public_key_path"))
            .and_then(toml::Value::as_str),
        Some(missing_key.display().to_string()).as_deref()
    );
    assert_eq!(
        sidecar_table
            .get("capability_seed")
            .and_then(|seed| seed.get("paths"))
            .and_then(toml::Value::as_array)
            .and_then(|paths| paths.last())
            .and_then(toml::Value::as_str),
        Some(seed_path.display().to_string()).as_deref()
    );
    remove_marker(&identity);
}

#[cfg(unix)]
#[test]
fn autostart_without_effective_key_preserves_no_mint_behavior() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = RunIdentity::new("no-capability-key");
    let handle = sandbox_handle(&identity, dir.path());

    let error = prepare_network_runtime(
        &handle,
        &enforcement_proof(),
        &SidecarEndpoint::Tcp {
            addr: "127.0.0.1:1".parse().expect("sidecar address"),
        },
        &identity,
        &autostart_flags(None),
        authority(None),
        &capability(CapabilitySource::Disabled, None),
    )
    .err()
    .expect("test binary cannot autostart as the Sidecar");

    assert!(
        matches!(
            error,
            RunError::SidecarReadyTimeout { .. } | RunError::SidecarStartupFailed { .. }
        ),
        "got: {error}"
    );
    let sidecar = read_synthesized_sidecar(&identity);
    assert!(
        sidecar
            .get("sidecar")
            .and_then(|sidecar| sidecar.get("authority"))
            .and_then(|authority| authority.get("public_key_path"))
            .is_none(),
        "no key should be synthesized when neither source configures one"
    );
    remove_marker(&identity);
}
