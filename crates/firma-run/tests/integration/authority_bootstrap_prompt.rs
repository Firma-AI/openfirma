//! Integration tests for the first-run Authority bootstrap prompt.
//!
//! These exercise the decision matrix inside `routing::resolve_authority`:
//! when the prompt fires, when it is bypassed, and what gets persisted.
//! A non-existent `firma_exe` demonstrates that selection does not prepare or
//! spawn the owned Authority before the orchestrator acquires its lock, while
//! still allowing assertions on prompt and persistence side effects.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use firma_config_loader::CONFIG_FILE_NAME;
use firma_run::authority::{AuthorityCli, AuthorityPromptIo};
use firma_run::error::RunError;
use firma_run::identity::RunIdentity;
use firma_run::routing::{AutostartFlags, ResolveAuthorityRequest, resolve_authority};

struct RecordingPrompt {
    tty: bool,
    answer: bool,
    confirm_calls: usize,
}

impl RecordingPrompt {
    fn new(tty: bool, answer: bool) -> Self {
        Self {
            tty,
            answer,
            confirm_calls: 0,
        }
    }
}

impl AuthorityPromptIo for RecordingPrompt {
    fn is_tty(&self) -> bool {
        self.tty
    }
    fn confirm(&mut self, _prompt: &str) -> std::io::Result<bool> {
        self.confirm_calls += 1;
        Ok(self.answer)
    }
}

fn fake_firma_exe(tmp: &std::path::Path) -> PathBuf {
    tmp.join("does-not-exist-firma")
}

fn reserve_default_authority_addr() -> tokio::net::TcpSocket {
    let address = "[::1]:50051".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let socket = tokio::net::TcpSocket::new_v6().unwrap();
        match socket.bind(address) {
            Ok(()) => return socket,
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("reserve default Authority address {address}: {error}"),
        }
    }
}

fn resolve_test_authority(
    tmp: &tempfile::TempDir,
    cfg: &std::path::Path,
    identity: &RunIdentity,
    cli: &AuthorityCli,
    prompt: &mut dyn AuthorityPromptIo,
) -> Result<firma_run::routing::ResolvedAuthority, RunError> {
    resolve_authority(
        ResolveAuthorityRequest {
            identity,
            flags: &AutostartFlags::default(),
            cli,
            profile_name: "developer",
            user_config_path: Some(cfg),
            user_config_dir: cfg.parent(),
            firma_exe: &fake_firma_exe(tmp.path()),
            capability_public_key_path: None,
            working_dir: tmp.path(),
            state_layout: &firma_runtime_state::RuntimeLayout::from_root(tmp.path().join("state")),
        },
        prompt,
    )
}

pub fn generated_mapping_file(profile: &str) -> tempfile::TempDir {
    let _address = reserve_default_authority_addr();
    let tmp = tempfile::tempdir().expect("temporary Authority config");
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    let identity = RunIdentity::new(*super::helper::agent_id(), profile);
    resolve_test_authority(
        &tmp,
        &cfg,
        &identity,
        &AuthorityCli::Unset,
        &mut RecordingPrompt::new(true, true),
    )
    .expect("bootstrap Authority mapping inputs");
    tmp
}

#[tokio::test]
async fn prompt_fires_when_no_commit_and_persists_on_yes() -> anyhow::Result<()> {
    let _default_authority_addr = reserve_default_authority_addr();
    for profile in ["generic", "vscode"] {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join(CONFIG_FILE_NAME);
        let identity = RunIdentity::new(*super::helper::agent_id(), profile);
        std::fs::write(
            &cfg,
            format!(
                "[sidecar.authority]\nagent_id = '{}'\n",
                super::helper::agent_id()
            ),
        )?;

        let mut prompt = RecordingPrompt::new(true, true);
        let resolved =
            resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)
                .expect("selection must defer local preparation");

        // Bootstrap path ran: prompt invoked + section persisted before planning.
        assert_eq!(prompt.confirm_calls, 1);
        let persisted = std::fs::read_to_string(&cfg).unwrap();
        assert!(persisted.contains("[authority]"), "got: {persisted}");
        assert!(
            persisted.contains(r#"listen_addr = "[::1]:0""#),
            "got: {persisted}"
        );
        assert!(resolved.owned.is_some());
        assert_eq!(
            resolved
                .owned
                .as_ref()
                .and_then(|owned| owned.user_config_path.as_deref()),
            Some(cfg.as_path())
        );
        let mappings = super::helper::mapping_snapshot(&cfg).await?;
        // The persisted file serves later runs of every profile, not only the
        // one that answered the prompt.
        for host in ["api.openai.com", "marketplace.visualstudio.com"] {
            assert!(
                mappings.rules.iter().any(|rule| rule.host == host),
                "{profile} bootstrap does not classify {host}"
            );
        }
        for rule in mappings
            .rules
            .iter()
            .filter(|rule| rule.method.as_deref() == Some("CONNECT"))
        {
            if profile == "vscode"
                && ["github.com", "api.github.com", "uploads.github.com"]
                    .contains(&rule.host.as_str())
            {
                continue;
            }
            assert!(
                mappings
                    .rules
                    .iter()
                    .any(|inner| inner.method.is_none() && inner.host == rule.host),
                "missing post-MITM coverage for {}",
                rule.host
            );
        }
        let marker = tempfile::tempdir_in(tmp.path())?;
        std::fs::write(
            marker.path().join("mapping-rules.toml"),
            "not the durable rules",
        )?;
        marker.close()?;
        let second =
            resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)?;
        assert!(second.owned.is_some());
        assert_eq!(prompt.confirm_calls, 1);
        assert_eq!(super::helper::mapping_snapshot(&cfg).await?, mappings);
    }
    Ok(())
}

#[test]
fn prompt_declined_returns_typed_error_and_does_not_persist() {
    let _default_authority_addr = reserve_default_authority_addr();
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    let identity = RunIdentity::new(*super::helper::agent_id(), "test");

    let mut prompt = RecordingPrompt::new(true, false);
    let err = resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)
        .err()
        .expect("declined prompt must surface a typed error");

    assert_eq!(prompt.confirm_calls, 1);
    assert!(
        matches!(err, RunError::AuthorityBootstrapDeclined),
        "{err:?}"
    );
    assert!(!cfg.exists(), "firma.toml must not be written on decline");
}

#[test]
fn no_tty_returns_typed_error_without_calling_confirm() {
    let _default_authority_addr = reserve_default_authority_addr();
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    let identity = RunIdentity::new(*super::helper::agent_id(), "test");

    let mut prompt = RecordingPrompt::new(false, true);
    let err = resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)
        .err()
        .expect("no-tty must surface a typed error");

    assert_eq!(prompt.confirm_calls, 0);
    assert!(matches!(err, RunError::AuthorityBootstrapNoTty), "{err:?}");
    assert!(!cfg.exists(), "firma.toml must not be written on no-tty");
}

#[test]
fn cli_local_skips_prompt_even_without_config() {
    let _default_authority_addr = reserve_default_authority_addr();
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    let identity = RunIdentity::new(*super::helper::agent_id(), "test");

    let mut prompt = RecordingPrompt::new(true, false);
    let resolved = resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Local, &mut prompt)
        .expect("selection must defer local preparation");

    // `--authority local` is a commitment: prompt must not be consulted.
    assert_eq!(prompt.confirm_calls, 0);
    assert!(!cfg.exists(), "CLI commitment must not trigger persistence");
    assert!(resolved.owned.is_some());
}

#[test]
fn config_authority_section_skips_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &cfg,
        "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"[::1]:0\"\n",
    )
    .unwrap();
    let identity = RunIdentity::new(*super::helper::agent_id(), "test");

    let mut prompt = RecordingPrompt::new(true, false);
    let resolved = resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)
        .expect("selection must defer local preparation");

    assert_eq!(prompt.confirm_calls, 0);
    assert!(resolved.owned.is_some());
}

#[tokio::test]
async fn authored_inputs_and_policies_survive_bootstrap_and_the_second_selection()
-> anyhow::Result<()> {
    let _address = reserve_default_authority_addr();
    let tmp = tempfile::tempdir()?;
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &cfg,
        format!(
            "[sidecar.authority]\nagent_id = '{}'\n",
            super::helper::agent_id()
        ),
    )?;
    std::fs::write(tmp.path().join("mapping-rules.toml"), "rules = []\n")?;
    let policies = tmp.path().join("policies");
    std::fs::create_dir(&policies)?;
    std::fs::write(
        policies.join("authored.cedar"),
        "forbid(principal, action, resource);",
    )?;
    let identity = RunIdentity::new(*super::helper::agent_id(), "generic");
    let mut prompt = RecordingPrompt::new(true, true);
    for _ in 0..2 {
        let selected =
            resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)?;
        assert_eq!(
            selected
                .owned
                .as_ref()
                .and_then(|owned| owned.user_config_path.as_deref()),
            Some(cfg.as_path())
        );
        let mappings = super::helper::mapping_snapshot(&cfg).await?;
        assert_eq!(mappings.rules, []);
        assert!(mappings.default_protected);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("mapping-rules.toml"))?,
            "rules = []\n"
        );
        assert_eq!(std::fs::read_dir(&policies)?.count(), 1);
        assert_eq!(
            std::fs::read_to_string(policies.join("authored.cedar"))?,
            "forbid(principal, action, resource);"
        );
    }
    assert_eq!(prompt.confirm_calls, 1);
    Ok(())
}

/// Earlier releases persisted exactly this section when the operator accepted
/// the bootstrap prompt. It names no mapping inputs because the Sidecar owned
/// them then; the committed local choice must keep working after an upgrade
/// with the generated defaults the prompt now writes, rather than rejecting a
/// file the operator never authored.
#[tokio::test]
async fn a_previously_bootstrapped_authority_section_keeps_resolving() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let cfg = tmp.path().join(CONFIG_FILE_NAME);
    std::fs::write(&cfg, "[authority]\nlisten_addr = \"[::1]:0\"\n")?;
    let identity = RunIdentity::new(*super::helper::agent_id(), "generic");

    let mut prompt = RecordingPrompt::new(true, false);
    let resolved =
        resolve_test_authority(&tmp, &cfg, &identity, &AuthorityCli::Unset, &mut prompt)?;

    assert_eq!(prompt.confirm_calls, 0);
    assert!(resolved.owned.is_some());
    let mappings = super::helper::mapping_snapshot(&cfg).await?;
    assert!(
        mappings
            .rules
            .iter()
            .any(|rule| rule.host == "api.openai.com"),
        "{mappings:?}"
    );
    Ok(())
}
