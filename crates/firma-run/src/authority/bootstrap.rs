//! First-run interactive bootstrap for the local Mini Authority.
//!
//! Triggered from `routing::resolve_authority` when no committed choice
//! exists (no `--authority` CLI value, no `[authority]` / `[sidecar.authority]`
//! section in `firma.toml`) and no local Authority is reachable.
//!
//! On `Y` the `[authority]` table is merged into `firma.toml` so subsequent
//! runs skip the prompt. The persisted section configures an ephemeral port
//! (`listen_addr = "[::1]:0"`) — the Authority kernel picks a free port when
//! the child binds.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use firma_config_loader::CONFIG_DIR_NAME;
use firma_config_loader::CONFIG_FILE_NAME;
use toml_edit::{DocumentMut, Item, Table, value};

use crate::authority::AuthorityPromptIo;
use crate::error::RunError;

/// User-visible prompt text. Mirrors spec §4 step 4.
pub const PROMPT_TEXT: &str = "No Authority is configured for this project.\n\
    firma run can start a local Mini Authority for development on loopback ([::1]) using a per-run ephemeral port.\n\
    This is suitable for a single developer on a trusted workstation.\n\n\
    Start a local Mini Authority?";

/// `listen_addr` value persisted on `Y`. `:0` makes the Authority kernel pick
/// a free loopback port at every spawn.
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
pub(crate) fn run_prompt(prompt: &mut dyn AuthorityPromptIo) -> Result<(), RunError> {
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
pub(crate) fn resolve_persist_target(existing_config: Option<&Path>) -> Result<PathBuf, RunError> {
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
/// `[authority]` table is left untouched. Generated mapping and policy inputs
/// are written next to the file unless authored ones already exist there.
///
/// # Errors
///
/// - [`RunError::ConfigParse`] when the existing file is not valid TOML.
/// - [`RunError::AuthorityUnknownProfile`] when `profile` is not registered.
/// - [`RunError::Internal`] on I/O or serialization failure.
pub(crate) fn persist_authority_section(path: &Path, profile: &str) -> Result<(), RunError> {
    let mut doc = read_document(path)?;
    if doc.as_table().contains_key("authority") {
        return Ok(());
    }
    let parent = config_dir(path);
    fs::create_dir_all(parent)
        .map_err(|e| RunError::Internal(format!("mkdir {}: {e}", parent.display())))?;

    let mut authority = Table::new();
    authority.set_implicit(false);
    authority.insert("listen_addr", value(DEFAULT_LISTEN_ADDR));
    authority.insert(
        "mapping_rules_paths",
        value(generated_mapping_paths(parent)?),
    );
    let enforcement =
        firma_authority::cedar_for(profile).map_err(|_| RunError::AuthorityUnknownProfile {
            name: profile.to_string(),
        })?;
    crate::authority::defaults::materialize_policy(&parent.join("policies"), profile, enforcement)?;
    crate::authority::defaults::materialize_policy(
        &parent.join("issuance-policies"),
        profile,
        crate::authority::defaults::issuance_policy(profile)?,
    )?;
    authority.insert("policy_dir", value("policies"));
    authority.insert("issuance_policy_dir", value("issuance-policies"));
    doc.as_table_mut()
        .insert("authority", Item::Table(authority));
    write_document(path, &doc)
}

/// Give an `[authority]` section written before the Authority owned mappings
/// the generated inputs the first-run prompt now persists.
///
/// Earlier releases persisted exactly `listen_addr = "[::1]:0"`, leaving
/// mappings to the Sidecar and policies to directories nothing created. Any
/// other section was authored and is left to validation, which requires
/// explicit mapping inputs. Policy directories are generated only where none
/// exist yet.
///
/// # Errors
///
/// - [`RunError::ConfigParse`] when the file is not valid TOML.
/// - [`RunError::AuthorityUnknownProfile`] when `profile` is not registered.
/// - [`RunError::Internal`] on I/O failure.
pub(crate) fn backfill_mapping_inputs(path: &Path, profile: &str) -> Result<(), RunError> {
    let mut doc = read_document(path)?;
    let Some(authority) = doc.get_mut("authority").and_then(Item::as_table_like_mut) else {
        return Ok(());
    };
    // Only the exact section earlier prompts wrote is repaired; any other
    // section was authored and must name its mapping inputs explicitly.
    let previously_generated = authority.len() == 1
        && authority
            .get("listen_addr")
            .and_then(Item::as_str)
            .is_some_and(|listen| listen == DEFAULT_LISTEN_ADDR);
    if !previously_generated {
        return Ok(());
    }
    let dir = config_dir(path);
    authority.insert("mapping_rules_paths", value(generated_mapping_paths(dir)?));
    let enforcement =
        firma_authority::cedar_for(profile).map_err(|_| RunError::AuthorityUnknownProfile {
            name: profile.to_string(),
        })?;
    for (default_dir, content) in [
        ("policies", enforcement),
        (
            "issuance-policies",
            crate::authority::defaults::issuance_policy(profile)?,
        ),
    ] {
        let default_dir = dir.join(default_dir);
        if !default_dir.exists() {
            crate::authority::defaults::materialize_policy(&default_dir, profile, content)?;
        }
    }
    write_document(path, &doc)?;
    tracing::info!(
        config = %path.display(),
        "added generated mapping inputs to the existing [authority] section"
    );
    Ok(())
}

/// Write the generated mapping file in `dir` unless one already exists, and
/// return the config-relative path list naming it.
fn generated_mapping_paths(dir: &Path) -> Result<toml_edit::Array, RunError> {
    let mapping_path = dir.join(GENERATED_MAPPING_FILE);
    if !mapping_path.exists() {
        fs::write(
            &mapping_path,
            crate::authority::defaults::persisted_mapping_rules(),
        )
        .map_err(|e| RunError::Internal(format!("write {}: {e}", mapping_path.display())))?;
    }
    Ok(toml_edit::Array::from_iter([GENERATED_MAPPING_FILE]))
}

const GENERATED_MAPPING_FILE: &str = "mapping-rules.toml";

fn config_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn read_document(path: &Path) -> Result<DocumentMut, RunError> {
    match fs::read_to_string(path) {
        Ok(text) => text
            .parse()
            .map_err(|e: toml_edit::TomlError| RunError::ConfigParse {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(e) => Err(RunError::Internal(format!(
            "read user config {}: {e}",
            path.display()
        ))),
    }
}

fn write_document(path: &Path, doc: &DocumentMut) -> Result<(), RunError> {
    fs::write(path, doc.to_string())
        .map_err(|e| RunError::Internal(format!("write {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persist_creates_file_with_section_when_missing() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME);
        persist_authority_section(&target, firma_authority::DEFAULT_PROFILE).unwrap();
        let contents = fs::read_to_string(&target).unwrap();
        assert!(contents.contains("[authority]"));
        assert!(contents.contains(r#"listen_addr = "[::1]:0""#));
    }

    #[test]
    fn persist_preserves_other_sections() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&target, "[run]\nprofile = \"generic\"\n").unwrap();
        persist_authority_section(&target, firma_authority::DEFAULT_PROFILE).unwrap();
        let contents = fs::read_to_string(&target).unwrap();
        assert!(contents.contains("[run]"), "got: {contents}");
        assert!(
            contents.contains("profile = \"generic\""),
            "got: {contents}"
        );
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
        persist_authority_section(&target, firma_authority::DEFAULT_PROFILE).unwrap();
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
        let err = persist_authority_section(&target, firma_authority::DEFAULT_PROFILE).unwrap_err();
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
