//! Resolve `AuthoritySelection` from CLI args, persisted user config,
//! and the y/N prompt.
//!
//! Precedence: CLI > persisted > prompt (only when both empty and TTY).
//! Persistence is gated strictly by the Y branch of the prompt — CLI
//! overrides and pre-existing persisted entries do not rewrite the file.

use std::path::Path;

use crate::authority::config::{AuthoritySection, persist_local, read_authority};
use crate::authority::prompt::AuthorityPromptIo;
use crate::error::RunError;

/// CLI-side selection (value of `--authority`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthorityCli {
    /// Flag not passed.
    #[default]
    Unset,
    /// `--authority local`.
    Local,
    /// `--authority <url>`.
    Remote(String),
}

/// Final, resolved Authority selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoritySelection {
    /// Use a local Mini Authority on loopback with a per-run ephemeral port;
    /// autostart if missing.
    Local,
    /// Use a remote Authority at the given URL.
    Remote(String),
}

/// User-visible prompt text. Spec §4 step 4 verbatim.
pub const PROMPT_TEXT: &str = "\
No Authority is configured for this project.
firma run can start a local Mini Authority for development on loopback ([::1]) using a per-run ephemeral port.
This is suitable for a single developer on a trusted workstation.

Start a local Mini Authority? [y/N]: ";

/// Resolve the selection.
///
/// # Errors
///
/// Returns:
///
/// - [`RunError::MissingAuthority`] when `no_autostart` is set and
///   nothing is configured.
/// - [`RunError::AuthorityPromptNoTty`] when no config exists and stdin
///   is not a TTY.
/// - [`RunError::AuthorityDeclined`] when the user answers N.
/// - [`RunError::ConfigParse`] / `Internal` on user-config I/O failure.
pub fn resolve(
    cli: &AuthorityCli,
    no_autostart: bool,
    user_config_path: &Path,
    prompt: &mut dyn AuthorityPromptIo,
) -> Result<AuthoritySelection, RunError> {
    match cli {
        AuthorityCli::Local => return Ok(AuthoritySelection::Local),
        AuthorityCli::Remote(url) => return Ok(AuthoritySelection::Remote(url.clone())),
        AuthorityCli::Unset => {}
    }

    if let Some(section) = read_authority(user_config_path)?
        && let Some(sel) = section_to_selection(&section)?
    {
        return Ok(sel);
    }

    if no_autostart {
        return Err(RunError::MissingAuthority);
    }
    if !prompt.is_tty() {
        return Err(RunError::AuthorityPromptNoTty);
    }
    let yes = prompt
        .confirm(PROMPT_TEXT)
        .map_err(|e| RunError::Internal(format!("read y/N answer: {e}")))?;
    if !yes {
        return Err(RunError::AuthorityDeclined);
    }
    persist_local(user_config_path)?;
    Ok(AuthoritySelection::Local)
}

fn section_to_selection(s: &AuthoritySection) -> Result<Option<AuthoritySelection>, RunError> {
    match s.r#type.as_deref() {
        Some("local") => Ok(Some(AuthoritySelection::Local)),
        Some("remote") => match &s.url {
            Some(url) if !url.is_empty() => Ok(Some(AuthoritySelection::Remote(url.clone()))),
            _ => Err(RunError::ConfigValidation(
                "[authority].type = \"remote\" requires `url`".to_string(),
            )),
        },
        Some(other) => Err(RunError::ConfigValidation(format!(
            "unknown [authority].type `{other}`"
        ))),
        None => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tempfile::tempdir;

    struct MockPrompt {
        tty: bool,
        answers: VecDeque<bool>,
        called: usize,
    }

    impl MockPrompt {
        fn new(tty: bool, answers: Vec<bool>) -> Self {
            Self {
                tty,
                answers: answers.into(),
                called: 0,
            }
        }
    }

    impl AuthorityPromptIo for MockPrompt {
        fn is_tty(&self) -> bool {
            self.tty
        }
        fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
            self.called += 1;
            Ok(self.answers.pop_front().unwrap_or(false))
        }
    }

    #[test]
    fn cli_local_wins_over_everything() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("none.toml");
        let mut prompt = MockPrompt::new(false, vec![]);
        let sel = resolve(&AuthorityCli::Local, true, &cfg, &mut prompt).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
        assert_eq!(prompt.called, 0);
    }

    #[test]
    fn cli_remote_wins_over_everything() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("none.toml");
        let mut prompt = MockPrompt::new(false, vec![]);
        let sel = resolve(
            &AuthorityCli::Remote("https://x".into()),
            true,
            &cfg,
            &mut prompt,
        )
        .unwrap();
        assert_eq!(sel, AuthoritySelection::Remote("https://x".into()));
    }

    #[test]
    fn persisted_local_returns_local_without_prompt() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        std::fs::write(&path, "[authority]\ntype = \"local\"\n").unwrap();
        let mut prompt = MockPrompt::new(true, vec![]);
        let sel = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
        assert_eq!(prompt.called, 0);
    }

    #[test]
    fn persisted_remote_returns_remote() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        std::fs::write(
            &path,
            "[authority]\ntype = \"remote\"\nurl = \"https://x\"\n",
        )
        .unwrap();
        let mut prompt = MockPrompt::new(false, vec![]);
        let sel = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap();
        assert_eq!(sel, AuthoritySelection::Remote("https://x".into()));
    }

    #[test]
    fn no_autostart_with_empty_errors_missing_authority() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        let mut prompt = MockPrompt::new(true, vec![true]);
        let err = resolve(&AuthorityCli::Unset, true, &path, &mut prompt).unwrap_err();
        assert!(matches!(err, RunError::MissingAuthority));
        assert_eq!(prompt.called, 0);
    }

    #[test]
    fn no_tty_with_empty_errors_no_tty() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        let mut prompt = MockPrompt::new(false, vec![]);
        let err = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap_err();
        assert!(matches!(err, RunError::AuthorityPromptNoTty));
    }

    #[test]
    fn tty_yes_persists_and_returns_local() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        let mut prompt = MockPrompt::new(true, vec![true]);
        let sel = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
        let persisted = read_authority(&path).unwrap().unwrap();
        assert_eq!(persisted.r#type.as_deref(), Some("local"));
    }

    #[test]
    fn tty_no_returns_declined_without_persist() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        let mut prompt = MockPrompt::new(true, vec![false]);
        let err = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap_err();
        assert!(matches!(err, RunError::AuthorityDeclined));
        assert!(read_authority(&path).unwrap().is_none() || !path.exists());
    }

    #[test]
    fn remote_section_without_url_errors() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        std::fs::write(&path, "[authority]\ntype = \"remote\"\n").unwrap();
        let mut prompt = MockPrompt::new(false, vec![]);
        let err = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap_err();
        assert!(matches!(err, RunError::ConfigValidation(_)));
    }

    #[test]
    fn unknown_type_errors() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("firma.toml");
        std::fs::write(&path, "[authority]\ntype = \"weird\"\n").unwrap();
        let mut prompt = MockPrompt::new(false, vec![]);
        let err = resolve(&AuthorityCli::Unset, false, &path, &mut prompt).unwrap_err();
        assert!(matches!(err, RunError::ConfigValidation(_)));
    }
}
