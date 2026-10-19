//! Scope of the file watch that triggers enforcement reloads.
//!
//! Single-file inputs (mapping files and an explicit schema) are watched
//! through their parent directories so editors that replace a file by rename
//! keep triggering reloads. Those directories may hold unrelated, frequently
//! written files, such as the Authority's own log, so events are filtered to
//! the configured inputs: reacting to every write in the directory would let
//! the reload log line trigger the next reload indefinitely.
//!
//! Mounted configuration, such as a Kubernetes `ConfigMap`, links each file
//! through a `..data` symlink and publishes an update by atomically
//! retargeting it, so no event names the configured file. The policy
//! directory belongs to the Authority, so any change beneath it counts. An
//! input also counts when the path it resolves to has changed. A watch follows
//! symlinks to the revision they named when it was registered, so the parent
//! of every symlink on an input's path is watched too: that is where the
//! retarget happens.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// The set of paths whose changes can alter an enforcement generation.
pub struct WatchedInputs {
    policy_dir: PathBuf,
    canonical_policy_dir: PathBuf,
    files: HashSet<PathBuf>,
    /// The policy directory and each single-file input, with the path it
    /// resolved to when last checked.
    targets: Vec<(PathBuf, PathBuf)>,
}

impl WatchedInputs {
    pub fn new<'a>(policy_dir: &Path, files: impl IntoIterator<Item = &'a Path>) -> Self {
        let files: Vec<&Path> = files.into_iter().collect();
        Self {
            policy_dir: policy_dir.to_path_buf(),
            canonical_policy_dir: canonical(policy_dir),
            files: files.iter().copied().map(identity).collect(),
            targets: std::iter::once(policy_dir)
                .chain(files)
                .map(|input| (input.to_path_buf(), canonical(input)))
                .collect(),
        }
    }

    /// Directories outside the recursively watched policy directory that must
    /// be watched non-recursively: the parent of each single-file input, and
    /// the parent of every symlink on the path of any input.
    pub fn file_parents<'a>(
        policy_dir: &Path,
        files: impl IntoIterator<Item = &'a Path>,
    ) -> BTreeSet<PathBuf> {
        let files: Vec<&Path> = files.into_iter().collect();
        let links = std::iter::once(policy_dir)
            .chain(files.iter().copied())
            .flat_map(Path::ancestors)
            .filter(|ancestor| ancestor.is_symlink())
            .map(parent)
            // A filesystem root would observe the whole host on some backends.
            .filter(|parent| parent.parent().is_some());
        files
            .iter()
            .copied()
            .map(parent)
            .chain(links)
            .filter(|parent| !parent.starts_with(policy_dir))
            .map(Path::to_path_buf)
            .collect()
    }

    /// Whether a change to `path` can alter the enforcement generation.
    ///
    /// Any path at or beneath the policy directory counts, including symlink
    /// targets and entries of a directory that was already removed; a reload
    /// that finds unchanged inputs publishes nothing.
    pub fn contains(&self, path: &Path) -> bool {
        if path.starts_with(&self.policy_dir) {
            return true;
        }
        let path = identity(path);
        self.files.contains(&path) || path.starts_with(&self.canonical_policy_dir)
    }

    /// Whether any input now resolves to a different path, as after a mounted
    /// configuration retargets a symlink it is reached through. Records the new
    /// targets, so each retarget is reported once.
    pub fn retargeted(&mut self) -> bool {
        let mut changed = false;
        for (file, target) in &mut self.targets {
            let current = canonical(file);
            if current != *target {
                *target = current;
                changed = true;
            }
        }
        changed
    }
}

/// The directory containing `file`, with a bare relative name resolving to
/// the current directory rather than the empty path the OS cannot watch.
pub fn parent(file: &Path) -> &Path {
    file.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// A comparable identity for `path` that survives removal of the file itself:
/// the canonical parent directory joined with the file name. Watch backends
/// may report canonical paths (for example through symlinked temporary
/// directories) or paths relative to how the watch was registered.
fn identity(path: &Path) -> PathBuf {
    path.file_name().map_or_else(
        || canonical(path),
        |name| canonical(parent(path)).join(name),
    )
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
