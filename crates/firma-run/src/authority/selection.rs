//! Resolve `AuthoritySelection` from CLI args and `firma.toml`.
//!
//! Precedence: CLI > `firma.toml`. Selection rule:
//!
//! - `[authority]` present in `firma.toml` → `Local` (autostart).
//! - `[sidecar.authority].url` present → `Remote(url)`.
//! - Neither → [`RunError::MissingAuthority`].

use std::path::Path;

use crate::authority::config::{AuthoritySection, read_authority};
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

/// Resolve the selection.
///
/// # Errors
///
/// Returns [`RunError::MissingAuthority`] when no CLI flag is set and
/// the user config carries neither `[authority]` nor
/// `[sidecar.authority].url`.
pub(crate) fn resolve(
    cli: &AuthorityCli,
    no_autostart: bool,
    user_config_path: Option<&Path>,
) -> Result<AuthoritySelection, RunError> {
    match cli {
        AuthorityCli::Local => return Ok(AuthoritySelection::Local),
        AuthorityCli::Remote(url) => return Ok(AuthoritySelection::Remote(url.clone())),
        AuthorityCli::Unset => {}
    }

    if let Some(path) = user_config_path
        && let Some(section) = read_authority(path)?
        && let Some(sel) = section_to_selection(&section)
    {
        return Ok(sel);
    }
    if no_autostart {
        return Err(RunError::MissingAuthority);
    }
    Ok(AuthoritySelection::Local)
}

fn section_to_selection(s: &AuthoritySection) -> Option<AuthoritySelection> {
    if s.local {
        return Some(AuthoritySelection::Local);
    }
    s.connect
        .as_ref()
        .and_then(|c| c.url.as_deref())
        .filter(|u| !u.is_empty())
        .map(|u| AuthoritySelection::Remote(u.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_config_loader::CONFIG_FILE_NAME;
    use tempfile::tempdir;

    #[test]
    fn cli_local_wins_over_everything() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("none.toml");
        let sel = resolve(&AuthorityCli::Local, true, Some(cfg.as_path())).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
    }

    #[test]
    fn cli_remote_wins_over_everything() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("none.toml");
        let sel = resolve(
            &AuthorityCli::Remote("https://x".into()),
            true,
            Some(cfg.as_path()),
        )
        .unwrap();
        assert_eq!(sel, AuthoritySelection::Remote("https://x".into()));
    }

    #[test]
    fn authority_section_implies_local() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "[authority]\nlisten_addr = \"127.0.0.1:0\"\n").unwrap();
        let sel = resolve(&AuthorityCli::Unset, false, Some(path.as_path())).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
    }

    #[test]
    fn sidecar_authority_url_only_returns_remote() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "[sidecar.authority]\nurl = \"https://x\"\n").unwrap();
        let sel = resolve(&AuthorityCli::Unset, false, Some(path.as_path())).unwrap();
        assert_eq!(sel, AuthoritySelection::Remote("https://x".into()));
    }

    #[test]
    fn empty_config_defaults_to_local_autostart() {
        let sel = resolve(&AuthorityCli::Unset, false, None).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
    }

    #[test]
    fn no_authority_keys_defaults_to_local_autostart() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "[run]\nprofile = \"generic\"\n").unwrap();
        let sel = resolve(&AuthorityCli::Unset, false, Some(path.as_path())).unwrap();
        assert_eq!(sel, AuthoritySelection::Local);
    }

    #[test]
    fn no_config_with_no_autostart_errors_missing_authority() {
        let err = resolve(&AuthorityCli::Unset, true, None).unwrap_err();
        assert!(matches!(err, RunError::MissingAuthority));
    }
}
