//! Cedar policy discovery for Policy Control.
//!
//! The TUI gets its policy rows from the same Cedar directory that the
//! Authority loads. Each discovered policy must carry an `@id(...)`
//! annotation; that id becomes the stable row identity and the display label is
//! derived later by the renderer.
//!
//! Discovery is intentionally read-only. The state reader is injectable so the
//! app can use the Cedar source reader while tests can count reads or provide
//! controlled states without touching the filesystem more than needed.

use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use cedar_policy::PolicySet;

use crate::control::{
    error::{ErrorMessage, PolicyDiscoveryError},
    toggle::{self, PolicyState},
};

// Discovery follows the Authority policy directory rather than a separate TUI
// settings file. Only Cedar sources are scanned, and each visible row must come
// from the Cedar-native `@id(...)` annotation so the policy file remains the
// single source of truth for both enforcement and control.
const CEDAR_EXTENSION: &str = "cedar";
const POLICY_ID_ANNOTATION: &str = "id";

type PolicyStateMap = HashMap<String, PolicyState>;
type PolicyStateReadFn = dyn Fn(&Path, &[String]) -> PolicyStateMap + Send + Sync;

/// Reads enabled/disabled state for policy ids in one Cedar file.
///
/// The reader is a small indirection around the Cedar state parser. It lets the
/// app load policy rows without knowing whether the states came from disk, a
/// test double, or a future cached source.
#[derive(Clone)]
pub struct PolicyStateReader(Arc<PolicyStateReadFn>);

impl PolicyStateReader {
    /// Creates a reader from a fn that accepts one Cedar file and the
    /// policy ids to inspect inside that file.
    #[must_use]
    pub fn new(read: impl Fn(&Path, &[String]) -> PolicyStateMap + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }

    /// Reads all requested policy states for one source file.
    #[must_use]
    pub(crate) fn read(&self, file: &Path, ids: &[String]) -> PolicyStateMap {
        self.0(file, ids)
    }
}

impl Default for PolicyStateReader {
    fn default() -> Self {
        Self::new(read_policy_states_for_file)
    }
}

impl fmt::Debug for PolicyStateReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PolicyStateReader")
    }
}

/// Policies discovered from one Authority policy directory.
///
/// The catalog keeps the resolved directory with the rows so status rendering
/// can report which policy source is being shown.
#[derive(Debug)]
pub struct PolicyCatalog {
    policy_dir: PathBuf,
    policies: Vec<PolicyMapping>,
}

impl PolicyCatalog {
    /// Directory that was scanned for Cedar policies.
    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }

    /// Discovered policy mappings in deterministic file order.
    pub fn policies(&self) -> &[PolicyMapping] {
        &self.policies
    }
}

/// One policy row discovered from a Cedar `@id(...)` annotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyMapping {
    /// Stable policy id from Cedar.
    pub id: String,
    /// Cedar file that contains the policy.
    pub file: PathBuf,
    /// State read from the Cedar source for this policy id.
    pub state: PolicyState,
}

/// Discovers Cedar policies in the given policy directory.
///
/// Files are scanned in deterministic order. Policies without `@id(...)` are
/// ignored, while empty or duplicate ids stop discovery because the TUI needs a
/// stable unique identity for every row it shows.
///
/// # Errors
///
/// Fails when the policy directory is missing or unreadable, when a Cedar file
/// cannot be read or parsed, or when discovered ids are empty or duplicated.
pub fn discover(
    policy_dir: &Path,
    state_reader: &PolicyStateReader,
) -> Result<PolicyCatalog, PolicyDiscoveryError> {
    let files = cedar_files(policy_dir)?;
    let mut ids = HashSet::new();
    let mut policies = Vec::new();

    for file in files {
        let source = fs::read_to_string(&file).map_err(|error| PolicyDiscoveryError::ReadFile {
            path: file.clone(),
            source: ErrorMessage::capture(error),
        })?;
        let policy_set =
            source
                .parse::<PolicySet>()
                .map_err(|error| PolicyDiscoveryError::ParseFile {
                    path: file.clone(),
                    source: ErrorMessage::capture(error),
                })?;

        let mut file_ids = Vec::new();
        for policy in policy_set.policies() {
            let Some(id) = policy.annotation(POLICY_ID_ANNOTATION) else {
                continue;
            };
            let id = id.trim();
            if id.is_empty() {
                return Err(PolicyDiscoveryError::EmptyId { path: file });
            }
            if !ids.insert(id.to_string()) {
                return Err(PolicyDiscoveryError::DuplicateId { id: id.to_string() });
            }

            file_ids.push(id.to_owned());
        }

        let states = state_reader.read(&file, &file_ids);
        for id in file_ids {
            policies.push(PolicyMapping {
                state: states
                    .get(&id)
                    .copied()
                    .unwrap_or(PolicyState::InvalidPolicy),
                id,
                file: file.clone(),
            });
        }
    }

    Ok(PolicyCatalog {
        policy_dir: policy_dir.to_path_buf(),
        policies,
    })
}

/// Reads policy states from one Cedar file through the Cedar source reader.
pub fn read_policy_states_for_file(path: &Path, policy_ids: &[String]) -> PolicyStateMap {
    toggle::read_policy_states(path, policy_ids)
}

fn cedar_files(policy_dir: &Path) -> Result<Vec<PathBuf>, PolicyDiscoveryError> {
    if !policy_dir.is_dir() {
        return Err(PolicyDiscoveryError::MissingDirectory {
            path: policy_dir.to_path_buf(),
        });
    }

    let mut entries = fs::read_dir(policy_dir)
        .map_err(|error| PolicyDiscoveryError::ReadDirectory {
            path: policy_dir.to_path_buf(),
            source: ErrorMessage::capture(error),
        })?
        .collect::<Result<Vec<_>, std::io::Error>>()
        .map_err(|error| PolicyDiscoveryError::ReadDirectory {
            path: policy_dir.to_path_buf(),
            source: ErrorMessage::capture(error),
        })?;

    entries.sort_by_key(fs::DirEntry::file_name);

    Ok(entries
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == CEDAR_EXTENSION))
        .collect())
}
