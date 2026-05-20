//! Thin Cedar policy-bundle directory reader for `firma policy test`.
//!
//! Reads every `*.cedar` file directly inside a directory (non-recursive),
//! sorted by file name for deterministic concatenation, joins their contents,
//! and parses the result into a single [`cedar_policy::PolicySet`]. There is
//! no async, no TTL, and no file watching: this is a one-shot offline read
//! used by the fixture test runner.
//!
//! The reader is fail-closed. An empty directory (no `.cedar` files), an
//! unreadable directory or file, or a Cedar parse error all yield [`Err`];
//! the caller maps that to a non-zero exit code so a broken bundle can never
//! silently authorize a fixture.

use std::path::{Path, PathBuf};

use cedar_policy::PolicySet;

/// Errors produced while reading and parsing a Cedar policy bundle directory.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// The bundle directory could not be listed.
    #[error("cannot read policy bundle directory '{path}': {source}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A `*.cedar` file could not be read.
    #[error("cannot read policy file '{path}': {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The directory contained no `*.cedar` files.
    #[error("policy bundle directory '{0}' contains no '*.cedar' files")]
    Empty(PathBuf),

    /// The concatenated Cedar source failed to parse.
    #[error("failed to parse Cedar policies in bundle '{path}': {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: cedar_policy::ParseErrors,
    },
}

/// Read every `*.cedar` file directly in `dir`, concatenate them in
/// file-name-sorted order, and parse the result into one [`PolicySet`].
///
/// The scan is non-recursive: files in subdirectories are ignored. Ordering
/// is by OS file name so the concatenation — and therefore the parsed policy
/// set and any generated policy ids — is deterministic across runs and
/// platforms.
///
/// # Errors
///
/// Returns [`BundleError::ReadDir`] if `dir` cannot be listed,
/// [`BundleError::ReadFile`] if a `*.cedar` file cannot be read,
/// [`BundleError::Empty`] if no `*.cedar` files are present, or
/// [`BundleError::Parse`] if the concatenated source is not valid Cedar.
pub fn read_policy_set(dir: &Path) -> Result<PolicySet, BundleError> {
    let entries = std::fs::read_dir(dir).map_err(|source| BundleError::ReadDir {
        path: dir.to_path_buf(),
        source,
    })?;

    let mut cedar_files: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| BundleError::ReadDir {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let is_cedar_file = path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("cedar"));
        if is_cedar_file {
            cedar_files.push(path);
        }
    }

    if cedar_files.is_empty() {
        return Err(BundleError::Empty(dir.to_path_buf()));
    }

    // Sort by OS file name for a deterministic, platform-independent
    // concatenation order.
    cedar_files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    let mut combined = String::new();
    for file in &cedar_files {
        let contents = std::fs::read_to_string(file).map_err(|source| BundleError::ReadFile {
            path: file.clone(),
            source,
        })?;
        combined.push_str(&contents);
        // Guard against a trailing-statement / leading-statement run-on when a
        // file does not end in a newline.
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
    }

    combined
        .parse::<PolicySet>()
        .map_err(|source| BundleError::Parse {
            path: dir.to_path_buf(),
            source,
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    #[test]
    fn multi_file_concat_in_sorted_order() {
        let dir = tmpdir();
        // Written out of order on purpose; sorted read order is a, b.
        fs::write(
            dir.path().join("b.cedar"),
            r#"permit(principal, action == Firma::Action::"code.read", resource);"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("a.cedar"),
            r#"permit(principal, action == Firma::Action::"issue.read", resource);"#,
        )
        .unwrap();

        let set = read_policy_set(dir.path()).expect("parse combined policy set");
        // Both files contributed exactly one policy each.
        assert_eq!(set.policies().count(), 2);
    }

    #[test]
    fn empty_dir_is_err() {
        let dir = tmpdir();
        let err = read_policy_set(dir.path()).unwrap_err();
        assert!(matches!(err, BundleError::Empty(_)), "got {err}");
    }

    #[test]
    fn dir_with_no_cedar_files_is_err() {
        let dir = tmpdir();
        fs::write(dir.path().join("notes.txt"), "not a policy").unwrap();
        let err = read_policy_set(dir.path()).unwrap_err();
        assert!(matches!(err, BundleError::Empty(_)), "got {err}");
    }

    #[test]
    fn bad_cedar_is_err() {
        let dir = tmpdir();
        fs::write(dir.path().join("bad.cedar"), "permit(principal action;").unwrap();
        let err = read_policy_set(dir.path()).unwrap_err();
        assert!(matches!(err, BundleError::Parse { .. }), "got {err}");
    }

    #[test]
    fn missing_dir_is_err() {
        let err = read_policy_set(Path::new("/nonexistent/firma-bundle-xyz")).unwrap_err();
        assert!(matches!(err, BundleError::ReadDir { .. }), "got {err}");
    }

    #[test]
    fn non_recursive_ignores_subdirs() {
        let dir = tmpdir();
        let sub = dir.path().join("nested");
        fs::create_dir(&sub).unwrap();
        // Only file lives in a subdirectory: must be ignored, leaving no
        // top-level `.cedar` files.
        fs::write(
            sub.join("deep.cedar"),
            r#"permit(principal, action == Firma::Action::"code.read", resource);"#,
        )
        .unwrap();
        let err = read_policy_set(dir.path()).unwrap_err();
        assert!(
            matches!(err, BundleError::Empty(_)),
            "subdir file must not be read; got {err}"
        );
    }
}
