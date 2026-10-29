//! State-directory TLS anchor adoption in `routing::resolve_authority`.
//!
//! A config that names no CA certificate adopts the one in the state directory,
//! and a local Authority whose material was wiped has it regenerated. Neither
//! may happen for an Authority this host does not own: its CA is issued
//! elsewhere, so there is nothing local to repair.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::assert_matches;
use std::net::TcpListener;

use firma_config_loader::CONFIG_FILE_NAME;
use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::error::RunError;
use firma_run::routing::{
    AutostartFlags, ResolveAuthorityRequest, ResolvedAuthority, resolve_authority,
};

struct PanicPrompt;
impl AuthorityPromptIo for PanicPrompt {
    fn is_tty(&self) -> bool {
        panic!("prompt should not be consulted");
    }
    fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
        panic!("prompt should not be invoked");
    }
}

/// Resolve against `config_body`, with a `firma` executable that cannot be
/// spawned. Any attempt to regenerate TLS material therefore surfaces as
/// `RunError::Internal`, which is how each test observes whether the
/// regeneration path was entered.
fn resolve(config_body: &str) -> Result<ResolvedAuthority, RunError> {
    resolve_beside_local_ca(config_body, LocalCa::Absent).0
}

/// Whether the state directory holds a local Authority CA.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalCa {
    Present,
    Absent,
}

/// The state directory inside the temporary directory a resolution ran in.
fn state_layout(tmp: &tempfile::TempDir) -> firma_runtime_state::RuntimeLayout {
    firma_runtime_state::RuntimeLayout::from_root(tmp.path().join("state"))
}

/// [`resolve`], with the state directory holding a local Authority CA when
/// `local_ca` is [`LocalCa::Present`]. Also returns the temporary directory
/// holding the config file and the state directory.
fn resolve_beside_local_ca(
    config_body: &str,
    local_ca: LocalCa,
) -> (Result<ResolvedAuthority, RunError>, tempfile::TempDir) {
    resolve_with_cli(config_body, local_ca, &AuthorityCli::Unset)
}

fn resolve_with_cli(
    config_body: &str,
    local_ca: LocalCa,
    cli: &AuthorityCli,
) -> (Result<ResolvedAuthority, RunError>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(&config_path, config_body).unwrap();
    let identity = firma_run::identity::RunIdentity::new(*super::helper::agent_id(), "test");
    let firma_exe = tmp.path().join("firma-does-not-exist");
    let state_layout = state_layout(&tmp);
    if local_ca == LocalCa::Present {
        std::fs::create_dir_all(state_layout.tls_dir()).unwrap();
        std::fs::write(state_layout.authority_tls_ca_certificate(), "ca").unwrap();
    }

    let resolved = resolve_authority(
        ResolveAuthorityRequest {
            identity: &identity,
            flags: &AutostartFlags::default(),
            cli,
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
    (resolved, tmp)
}

/// A remote `https://` Authority owns its own TLS identity. Adopting the
/// state-directory CA for it would pin a CA this host minted against a server
/// it never issued a certificate to; regenerating it would turn every run into
/// a local `firma authority init-tls`. An Authority whose physical route leaves
/// this host is remote even at a loopback URL.
#[test]
fn a_remote_https_authority_neither_adopts_nor_regenerates_local_tls_material() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let (resolved, _) = resolve_beside_local_ca(
        &format!(
            "[sidecar.authority]\nurl = \"https://{address}\"\nconnect_addr = \"192.0.2.10:{}\"\n",
            address.port()
        ),
        LocalCa::Present,
    );

    assert_eq!(
        resolved
            .expect("a remote https Authority must resolve without local TLS regeneration")
            .ca_cert_path,
        None,
        "a config that pinned no CA must not acquire the local state-directory one for a remote Authority"
    );

    // A pinned CA that is missing is reported by the Sidecar, not reissued:
    // without an `[authority]` section the selection is remote, and
    // regenerating would run the nonexistent `firma` and fail.
    let missing = std::env::temp_dir().join("firma-test-missing-remote-ca.crt");
    let resolved = resolve(&format!(
        "[sidecar.authority]\nurl = \"https://{address}\"\nca_cert_paths = [{:?}]\n",
        missing.display().to_string()
    ))
    .expect("a remote https Authority with a missing pinned CA must resolve unchanged");
    assert_eq!(
        resolved.trust,
        firma_sidecar::config::AuthorityTrust::CustomCas(vec![missing])
    );
    assert_eq!(
        resolved.ca_cert_path, None,
        "a CA the config names passes through the template; only an adopted one is injected"
    );
}

/// Where the Authority runs, not who started it, decides: an Authority started
/// on its own at a loopback URL is still the one the local CA signed.
#[test]
fn an_https_authority_at_a_loopback_url_adopts_the_local_ca() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let (resolved, tmp) = resolve_beside_local_ca(
        &format!("[sidecar.authority]\nurl = \"https://{address}\"\n"),
        LocalCa::Present,
    );

    assert_eq!(
        resolved
            .expect("a loopback https Authority must resolve")
            .ca_cert_path,
        Some(state_layout(&tmp).authority_tls_ca_certificate())
    );
}

/// The recovery path itself: a local Authority reached over TLS whose CA
/// certificate is gone (a wiped `XDG_RUNTIME_DIR`) still has its material
/// regenerated, even though the config names no `ca_cert_paths`.
#[test]
fn a_local_tls_authority_regenerates_its_wiped_ca_material() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let result = resolve(&format!(
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"{address}\"\n\n[sidecar.authority]\nurl = \"https://{address}\"\n"
    ));

    match result {
        Err(RunError::Internal(message)) => assert!(
            message.contains("init-tls"),
            "expected a TLS regeneration attempt, got: {message}"
        ),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("regeneration must be attempted through the configured firma executable"),
    }
}

/// URL schemes are case-insensitive, and the Sidecar reads them through a URI
/// parser that normalizes them: it treats `HTTPS://` as TLS and refuses to start
/// without a CA certificate. A byte-prefix test here disagrees, so the run skips
/// the recovery and then dies on the Sidecar's own validation instead.
#[test]
fn an_uppercase_https_scheme_still_triggers_tls_recovery() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let result = resolve(&format!(
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"{address}\"\n\n[sidecar.authority]\nurl = \"HTTPS://{address}\"\n"
    ));

    match result {
        Err(RunError::Internal(message)) => assert!(
            message.contains("init-tls"),
            "expected a TLS regeneration attempt, got: {message}"
        ),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("an uppercase https scheme must be recognized as TLS"),
    }
}

/// An `http://` local Authority has no TLS identity to repair, so the CA
/// position in the state directory stays unclaimed.
#[test]
fn a_plaintext_local_authority_claims_no_ca_position() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();

    let resolved = resolve(&format!(
        "[sidecar.authority]\nurl = \"http://{address}\"\n"
    ))
    .expect("a plaintext Authority must resolve");

    assert_eq!(resolved.ca_cert_path, None);
}

/// A config whose only trust source is switched off is refused as
/// configuration, before any probe or mint could reach the Authority: the
/// listener standing in for it sees no connection.
#[test]
fn a_config_that_trusts_nothing_is_refused_before_any_connection() {
    let listener = super::helper::unreached_authority();
    let address = listener.local_addr().unwrap();

    let Err(error) = resolve(&format!(
        "[sidecar.authority]\nurl = \"https://{address}\"\ndisable_platform_roots = true\n"
    )) else {
        panic!("disabling the platform roots with no CA must be refused");
    };

    assert_matches!(&error, RunError::ConfigValidation(_));
    insta::assert_snapshot!(error.to_string(), @"config validation failed: sidecar.authority: authority.disable_platform_roots = true requires authority.ca_cert_paths");
    super::helper::assert_never_contacted(&listener);
}

/// A `ca_cert_paths` list is operator material: even for a local TLS
/// Authority with a missing entry, nothing is regenerated and no CA position
/// in the state directory is claimed. The Sidecar reports the missing file.
#[test]
fn a_ca_list_of_a_local_authority_is_never_regenerated() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let (resolved, tmp) = resolve_beside_local_ca(
        &format!(
            "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"{address}\"\n\n[sidecar.authority]\nurl = \"https://{address}\"\nca_cert_paths = [\"missing-corp-ca.pem\"]\n"
        ),
        LocalCa::Absent,
    );
    let resolved = resolved.expect("a listed CA must not trigger a regeneration attempt");

    assert_eq!(
        resolved.trust,
        firma_sidecar::config::AuthorityTrust::CustomCas(vec![
            tmp.path().join("missing-corp-ca.pem")
        ]),
        "a relative entry is resolved against the config directory"
    );
    assert_eq!(resolved.ca_cert_path, None);
}

/// A `[sidecar.authority]` section that sets only the new keys is still a
/// section: with the URL coming from `--authority`, the switch it carries is
/// honored rather than dropped as an empty section.
#[test]
fn a_section_with_only_the_new_keys_is_kept() {
    let listener = super::helper::unreached_authority();
    let address = listener.local_addr().unwrap();

    let (resolved, _) = resolve_with_cli(
        "[sidecar.authority]\ndisable_platform_roots = true\n",
        LocalCa::Absent,
        &AuthorityCli::Remote(format!("https://{address}")),
    );

    let Err(error) = resolved else {
        panic!("the switch must not be lost with the section");
    };
    assert_matches!(&error, RunError::ConfigValidation(_));
    insta::assert_snapshot!(error.to_string(), @"config validation failed: sidecar.authority: authority.disable_platform_roots = true requires authority.ca_cert_paths");
    super::helper::assert_never_contacted(&listener);
}

/// A blank CA entry names no file: it is refused while the config is read,
/// before any probe could reach the Authority.
#[test]
fn a_blank_ca_entry_is_refused_before_any_connection() {
    let listener = super::helper::unreached_authority();
    let address = listener.local_addr().unwrap();

    let Err(error) = resolve(&format!(
        "[sidecar.authority]\nurl = \"https://{address}\"\nca_cert_paths = [\"corp.pem\", \"\"]\n"
    )) else {
        panic!("a blank CA entry must be refused");
    };

    assert_matches!(&error, RunError::ConfigValidation(_));
    insta::assert_snapshot!(error.to_string(), @"config validation failed: sidecar.authority: authority.ca_cert_paths entries must not be empty");
    super::helper::assert_never_contacted(&listener);
}

/// The state directory's CA is regenerated for a local TLS Authority also
/// when the list names it next to an operator CA.
#[test]
fn a_listed_state_directory_ca_of_a_local_authority_is_regenerated() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    match resolve(&format!(
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"{address}\"\n\n[sidecar.authority]\nurl = \"https://{address}\"\nca_cert_paths = [\"corp-ca.pem\", \"state/tls/authority-ca.crt\"]\n"
    )) {
        Err(RunError::Internal(message)) => assert!(
            message.contains("init-tls"),
            "expected a TLS regeneration attempt, got: {message}"
        ),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("a listed, missing state-directory CA must be regenerated"),
    }
}
