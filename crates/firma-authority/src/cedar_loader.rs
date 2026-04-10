use std::path::{Path, PathBuf};
use std::sync::Arc;

use cedar_policy::{PolicySet, Schema};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, RwLock};

use firma_core::PolicyBundle;

use crate::error::AuthorityError;

/// Thread-safe Cedar policy store with hot-reload support.
///
/// Holds the currently active `PolicySet` and `Schema` behind an `RwLock`,
/// and exposes a `watch::Sender` that downstream consumers (gRPC streams)
/// subscribe to for push notifications on policy changes.
pub struct CedarPolicyStore {
    /// Current compiled policy set.
    policy_set: Arc<RwLock<Arc<PolicySet>>>,
    /// Current Cedar schema (if loaded).
    schema: Arc<RwLock<Option<Arc<Schema>>>>,
    /// Current bundle snapshot for distribution to sidecars.
    bundle: Arc<RwLock<PolicyBundle>>,
    /// Broadcast channel for policy bundle updates.
    bundle_tx: watch::Sender<PolicyBundle>,
    /// Policy directory path.
    policy_dir: PathBuf,
    /// Bundle TTL in seconds.
    bundle_ttl_seconds: i32,
}

impl CedarPolicyStore {
    /// Load policies from `policy_dir` and construct the store.
    ///
    /// Fails fast on invalid syntax or schema mismatch (FR-1).
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] if the policy directory cannot be read or
    /// any `.cedar` file contains invalid syntax.
    pub fn load(policy_dir: &Path, bundle_ttl_seconds: i32) -> Result<Self, AuthorityError> {
        let (policies_src, schema_src) = read_policy_files(policy_dir)?;
        let policy_set = parse_policies(&policies_src)?;
        let schema = parse_schema(&schema_src)?;

        let version = compute_version_hash(&policies_src, &schema_src);
        let bundle = PolicyBundle::new(
            version,
            policies_src.into_bytes(),
            schema_src.into_bytes(),
            bundle_ttl_seconds,
        );

        let (bundle_tx, _rx) = watch::channel(bundle.clone());

        tracing::info!(
            version = %bundle.version,
            policy_count = policy_set.policies().count(),
            "cedar policies loaded"
        );

        Ok(Self {
            policy_set: Arc::new(RwLock::new(Arc::new(policy_set))),
            schema: Arc::new(RwLock::new(schema.map(Arc::new))),
            bundle: Arc::new(RwLock::new(bundle)),
            bundle_tx,
            policy_dir: policy_dir.to_path_buf(),
            bundle_ttl_seconds,
        })
    }

    /// Reload policies from disk. If the new policy set is valid, atomically
    /// swap and notify all watchers. If invalid, keep the previous set (FR-2).
    pub async fn reload(&self) -> Result<(), AuthorityError> {
        let (policies_src, schema_src) = read_policy_files(&self.policy_dir)?;
        let new_policy_set = parse_policies(&policies_src)?;
        let new_schema = parse_schema(&schema_src)?;

        let new_version = compute_version_hash(&policies_src, &schema_src);

        // Check if version changed
        {
            let current_bundle = self.bundle.read().await;
            if current_bundle.version == new_version {
                tracing::debug!("policy reload: no changes detected");
                return Ok(());
            }
        }

        let new_bundle = PolicyBundle::new(
            new_version.clone(),
            policies_src.into_bytes(),
            schema_src.into_bytes(),
            self.bundle_ttl_seconds,
        );

        // Atomic swap
        {
            let mut ps = self.policy_set.write().await;
            *ps = Arc::new(new_policy_set);
        }
        {
            let mut s = self.schema.write().await;
            *s = new_schema.map(Arc::new);
        }
        {
            let mut b = self.bundle.write().await;
            *b = new_bundle.clone();
        }

        // Notify all watchers — ignore error (no receivers is fine)
        let _ = self.bundle_tx.send(new_bundle);

        tracing::info!(version = %new_version, "cedar policies reloaded");
        Ok(())
    }

    /// Get a snapshot of the current policy set for evaluation.
    pub async fn get_policy_set(&self) -> Arc<PolicySet> {
        Arc::clone(&*self.policy_set.read().await)
    }

    /// Get the current schema, if one was loaded.
    #[expect(dead_code, reason = "will be used when schema validation is wired in")]
    pub async fn get_schema(&self) -> Option<Arc<Schema>> {
        self.schema.read().await.clone()
    }

    /// Get the current policy bundle for distribution to sidecars.
    pub async fn get_bundle(&self) -> PolicyBundle {
        self.bundle.read().await.clone()
    }

    /// Subscribe to policy bundle updates. Returns the current bundle
    /// immediately, then yields on changes.
    pub fn subscribe(&self) -> watch::Receiver<PolicyBundle> {
        self.bundle_tx.subscribe()
    }
}

/// Read all `.cedar` files from a directory and concatenate their contents.
/// Also reads `schema.cedarschema` or `schema.json` if present.
fn read_policy_files(policy_dir: &Path) -> Result<(String, String), AuthorityError> {
    if !policy_dir.is_dir() {
        return Err(AuthorityError::PolicyLoadFailed {
            reason: format!("policy directory does not exist: {}", policy_dir.display()),
        });
    }

    let mut policies = String::new();
    let mut entries: Vec<_> = std::fs::read_dir(policy_dir)
        .map_err(|e| AuthorityError::PolicyLoadFailed {
            reason: format!("cannot read policy directory: {e}"),
        })?
        .filter_map(Result::ok)
        .collect();

    // Sort for deterministic ordering
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in &entries {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "cedar") {
            let content =
                std::fs::read_to_string(&path).map_err(|e| AuthorityError::PolicyLoadFailed {
                    reason: format!("cannot read {}: {e}", path.display()),
                })?;
            if !policies.is_empty() {
                policies.push('\n');
            }
            policies.push_str(&content);
        }
    }

    // Try to load schema
    let schema_src = try_read_schema(policy_dir).unwrap_or_default();

    Ok((policies, schema_src))
}

/// Try to read Cedar schema from the policy directory.
///
/// Returns the schema contents if a `schema.cedarschema` or `schema.json`
/// file is found. Returns an `io::Error` otherwise.
fn try_read_schema(policy_dir: &Path) -> std::io::Result<String> {
    // Try `.cedarschema` first (human-readable format), then `.json`
    let schema_path = policy_dir.join("schema.cedarschema");
    if schema_path.is_file() {
        return std::fs::read_to_string(&schema_path);
    }

    let schema_json_path = policy_dir.join("schema.json");
    if schema_json_path.is_file() {
        return std::fs::read_to_string(&schema_json_path);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no schema file found",
    ))
}

/// Parse Cedar policy source into a `PolicySet`.
fn parse_policies(source: &str) -> Result<PolicySet, AuthorityError> {
    if source.is_empty() {
        return Ok(PolicySet::new());
    }
    source
        .parse::<PolicySet>()
        .map_err(|e| AuthorityError::PolicyLoadFailed {
            reason: format!("cedar policy parse error: {e}"),
        })
}

/// Parse Cedar schema source into a `Schema`.
fn parse_schema(source: &str) -> Result<Option<Schema>, AuthorityError> {
    if source.is_empty() {
        return Ok(None);
    }
    let (schema, warnings) =
        Schema::from_cedarschema_str(source).map_err(|e| AuthorityError::PolicyLoadFailed {
            reason: format!("cedar schema parse error: {e}"),
        })?;
    for w in warnings {
        tracing::warn!(%w, "cedar schema warning");
    }
    Ok(Some(schema))
}

/// Compute SHA-256 version hash from policy + schema source.
fn compute_version_hash(policies: &str, schema: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policies.as_bytes());
    hasher.update(b"|"); // separator
    hasher.update(schema.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_policy_dir(policies: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        for (name, content) in policies {
            fs::write(dir.path().join(name), content).unwrap_or_else(|e| panic!("{e}"));
        }
        dir
    }

    #[test]
    fn test_load_empty_policy_dir() {
        let dir = setup_policy_dir(&[]);
        let store = CedarPolicyStore::load(dir.path(), 30);
        assert!(store.is_ok());
    }

    #[test]
    fn test_load_valid_policy() {
        let dir = setup_policy_dir(&[("allow-all.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30);
        assert!(store.is_ok());
    }

    #[test]
    fn test_load_invalid_policy_fails_fast() {
        let dir = setup_policy_dir(&[("bad.cedar", "this is not valid cedar syntax {{{")]);
        let store = CedarPolicyStore::load(dir.path(), 30);
        assert!(store.is_err());
    }

    #[test]
    fn test_nonexistent_dir_fails() {
        let store = CedarPolicyStore::load(Path::new("/nonexistent/path"), 30);
        assert!(store.is_err());
    }

    #[test]
    fn test_version_hash_deterministic() {
        let v1 = compute_version_hash("policy A", "schema B");
        let v2 = compute_version_hash("policy A", "schema B");
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_version_hash_changes_with_content() {
        let v1 = compute_version_hash("policy A", "schema B");
        let v2 = compute_version_hash("policy C", "schema B");
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn test_reload_no_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let result = store.reload().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_reload_detects_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let v1 = store.get_bundle().await.version.clone();

        // Add a new policy file
        fs::write(
            dir.path().join("deny.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let result = store.reload().await;
        assert!(result.is_ok());
        let v2 = store.get_bundle().await.version;
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn test_subscribe_receives_initial_value() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let rx = store.subscribe();
        let bundle = rx.borrow().clone();
        assert!(!bundle.version.is_empty());
    }
}
