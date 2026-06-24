//! First-run interactive bootstrap for the local Mini Authority.
//!
//! Triggered from `routing::resolve_authority` when no committed choice
//! exists (no `--authority` CLI value, no `[authority]` / `[sidecar.authority]`
//! section in `firma.toml`) and no local Authority is reachable.
//!
//! On `Y` the `[authority]` table is merged into `firma.toml` so subsequent
//! runs skip the prompt. The persisted section configures an ephemeral port
//! (`listen_addr = "[::1]:0"`) — the supervisor picks a free port on each
//! spawn (`select_loopback_v6_port`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use firma_config::CONFIG_DIR_NAME;
use firma_config::CONFIG_FILE_NAME;
use toml_edit::{DocumentMut, Item, Table, value};

use crate::authority::AuthorityPromptIo;
use crate::error::RunError;

/// User-visible prompt text. Mirrors spec §4 step 4.
pub const PROMPT_TEXT: &str = "No Authority is configured for this project.\n\
    firma run can start a local Mini Authority for development on loopback ([::1]) using a per-run ephemeral port.\n\
    This is suitable for a single developer on a trusted workstation.\n\n\
    Start a local Mini Authority?";

/// `listen_addr` value persisted on `Y`. `:0` makes the supervisor pick a
/// free loopback port at every spawn (`select_loopback_v6_port`).
const DEFAULT_LISTEN_ADDR: &str = "[::1]:0";

/// Run the y/N prompt and surface the answer as typed errors.
///
/// Returns `Ok(())` on `Y` so the caller can proceed to persist + spawn.
///
/// # Errors
///
/// - [`RunError::AuthorityBootstrapNoTty`] when stdin/stderr is not a TTY.
/// - [`RunError::AuthorityBootstrapDeclined`] when the user answers `N`.
/// - [`RunError::Internal`] on terminal I/O failure.
pub fn run_prompt(prompt: &mut dyn AuthorityPromptIo) -> Result<(), RunError> {
    if !prompt.is_tty() {
        return Err(RunError::AuthorityBootstrapNoTty);
    }
    let yes = prompt
        .confirm(PROMPT_TEXT)
        .map_err(|e| RunError::Internal(format!("read y/N answer: {e}")))?;
    if !yes {
        return Err(RunError::AuthorityBootstrapDeclined);
    }
    Ok(())
}

/// Decide where to persist the generated `[authority]` section.
///
/// Reuses an existing `firma.toml` when one was discovered by config
/// resolution; otherwise targets `<cwd>/.firma/firma.toml`.
///
/// # Errors
///
/// Returns [`RunError::Internal`] if the current working directory
/// cannot be read.
pub fn resolve_persist_target(existing_config: Option<&Path>) -> Result<PathBuf, RunError> {
    if let Some(path) = existing_config {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|e| RunError::Internal(format!("read cwd for firma.toml persist target: {e}")))?;
    Ok(cwd.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME))
}

/// Merge an `[authority]` table into `path` via a toml round-trip.
///
/// Existing sections/comments survive the round-trip; parent directories
/// and the file are created when missing. Idempotent: an existing
/// `[authority]` table is left untouched.
///
/// # Errors
///
/// - [`RunError::ConfigParse`] when the existing file is not valid TOML.
/// - [`RunError::Internal`] on I/O or serialization failure.
pub fn persist_authority_section(path: &Path) -> Result<(), RunError> {
    let mut doc: DocumentMut = match fs::read_to_string(path) {
        Ok(text) => text
            .parse()
            .map_err(|e: toml_edit::TomlError| RunError::ConfigParse {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => DocumentMut::new(),
        Err(e) => {
            return Err(RunError::Internal(format!(
                "read user config {}: {e}",
                path.display()
            )));
        }
    };

    if doc.as_table().contains_key("authority") {
        return Ok(());
    }

    let mut authority = Table::new();
    authority.set_implicit(false);
    authority.insert("listen_addr", value(DEFAULT_LISTEN_ADDR));
    doc.as_table_mut()
        .insert("authority", Item::Table(authority));

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", parent.display())))?;
    }

    fs::write(path, doc.to_string())
        .map_err(|e| RunError::Internal(format!("write {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persist_creates_file_with_section_when_missing() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME);
        persist_authority_section(&target).unwrap();
        let contents = fs::read_to_string(&target).unwrap();
        assert!(contents.contains("[authority]"));
        assert!(contents.contains(r#"listen_addr = "[::1]:0""#));
    }

    #[test]
    fn persist_preserves_other_sections() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&target, "[other]\nkeep = true\n").unwrap();
        persist_authority_section(&target).unwrap();
        let contents = fs::read_to_string(&target).unwrap();
        assert!(contents.contains("[other]"), "got: {contents}");
        assert!(contents.contains("keep = true"), "got: {contents}");
        assert!(contents.contains("[authority]"), "got: {contents}");
        assert!(
            contents.contains(r#"listen_addr = "[::1]:0""#),
            "got: {contents}"
        );
    }

    #[test]
    fn persist_is_idempotent_when_section_already_present() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join(CONFIG_FILE_NAME);
        let original = "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n";
        fs::write(&target, original).unwrap();
        persist_authority_section(&target).unwrap();
        let contents = fs::read_to_string(&target).unwrap();
        assert!(contents.contains("127.0.0.1:50051"), "got: {contents}");
        assert!(
            !contents.contains("[::1]:0"),
            "should not overwrite existing addr; got: {contents}"
        );
    }

    #[test]
    fn persist_rejects_malformed_toml() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&target, "not = valid = toml\n").unwrap();
        let err = persist_authority_section(&target).unwrap_err();
        assert!(matches!(err, RunError::ConfigParse { .. }));
    }

    #[test]
    fn resolve_persist_target_prefers_existing_config() {
        let tmp = tempdir().unwrap();
        let cfg = tmp.path().join("custom.toml");
        let resolved = resolve_persist_target(Some(cfg.as_path())).unwrap();
        assert_eq!(resolved, cfg);
    }

    #[test]
    fn resolve_persist_target_falls_back_to_cwd_dotfirma() {
        let resolved = resolve_persist_target(None).unwrap();
        assert!(resolved.ends_with(Path::new(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME)));
    }

    struct MockPrompt {
        tty: bool,
        answer: bool,
        called: usize,
    }

    impl AuthorityPromptIo for MockPrompt {
        fn is_tty(&self) -> bool {
            self.tty
        }
        fn confirm(&mut self, _prompt: &str) -> io::Result<bool> {
            self.called += 1;
            Ok(self.answer)
        }
    }

    #[test]
    fn run_prompt_yes_returns_ok() {
        let mut p = MockPrompt {
            tty: true,
            answer: true,
            called: 0,
        };
        run_prompt(&mut p).unwrap();
        assert_eq!(p.called, 1);
    }

    #[test]
    fn run_prompt_no_returns_declined() {
        let mut p = MockPrompt {
            tty: true,
            answer: false,
            called: 0,
        };
        let err = run_prompt(&mut p).unwrap_err();
        assert!(matches!(err, RunError::AuthorityBootstrapDeclined));
        assert_eq!(p.called, 1);
    }

    #[test]
    fn run_prompt_no_tty_returns_no_tty_without_calling_confirm() {
        let mut p = MockPrompt {
            tty: false,
            answer: true,
            called: 0,
        };
        let err = run_prompt(&mut p).unwrap_err();
        assert!(matches!(err, RunError::AuthorityBootstrapNoTty));
        assert_eq!(p.called, 0);
    }
}
