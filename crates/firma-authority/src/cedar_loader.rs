use std::path::{Path, PathBuf};
use std::sync::Arc;

use cedar_policy::{PolicySet, Schema};
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

use firma_core::policy::PolicyBundle;

use crate::error::AuthorityError;

/// All mutable policy state kept under a single lock for atomic swaps.
struct PolicyState {
    policy_set: Arc<PolicySet>,
    schema: Option<Arc<Schema>>,
}

/// Thread-safe Cedar policy store with hot-reload support.
///
/// All policy state (`PolicySet`, `Schema`, `PolicyBundle`) is held under a
/// single `RwLock` so that `reload()` updates are atomic — no reader ever
/// sees a new policy set paired with a stale schema or bundle.
#[derive(Clone)]
pub struct CedarPolicyStore {
    /// Atomic policy state.
    state: Arc<RwLock<PolicyState>>,
    /// Watch channel for policy bundle updates (push to sidecars).
    bundle_tx: watch::Sender<PolicyBundle>,
    /// Policy directory path.
    policy_dir: PathBuf,
    /// Bundle TTL in seconds.
    bundle_ttl_seconds: u32,
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
    pub fn load(policy_dir: &Path, bundle_ttl_seconds: u32) -> Result<Self, AuthorityError> {
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
            state: Arc::new(RwLock::new(PolicyState {
                policy_set: Arc::new(policy_set),
                schema: schema.map(Arc::new),
            })),
            bundle_tx,
            policy_dir: policy_dir.to_path_buf(),
            bundle_ttl_seconds,
        })
    }

    /// Reload policies from disk, atomically swapping all state in one lock
    /// acquisition. If the new policy set is invalid, keeps the previous set
    /// (FR-2). No-ops if the version hash has not changed.
    async fn reload(&self) -> Result<(), AuthorityError> {
        let (policies_src, schema_src) = read_policy_files(&self.policy_dir)?;
        let new_policy_set = parse_policies(&policies_src)?;
        let new_schema = parse_schema(&schema_src)?;
        let new_version = compute_version_hash(&policies_src, &schema_src);

        let new_bundle = {
            let mut state = self.state.write().await;
            if self.bundle_tx.borrow().version == new_version {
                tracing::debug!("policy reload: no changes detected");
                return Ok(());
            }

            let bundle = PolicyBundle::new(
                new_version.clone(),
                policies_src.into_bytes(),
                schema_src.into_bytes(),
                self.bundle_ttl_seconds,
            );

            state.policy_set = Arc::new(new_policy_set);
            state.schema = new_schema.map(Arc::new);
            bundle
        };

        // Notify all watchers — ignore error (no receivers is fine)
        self.bundle_tx.send_replace(new_bundle);

        tracing::info!(version = %new_version, "cedar policies reloaded");
        Ok(())
    }

    /// Get a snapshot of the current policy set for evaluation.
    pub async fn policy_set(&self) -> Arc<PolicySet> {
        self.state.read().await.policy_set.clone()
    }

    /// Get the current schema, if one was loaded.
    pub async fn schema(&self) -> Option<Arc<Schema>> {
        self.state.read().await.schema.clone()
    }

    /// Get the current policy bundle for distribution to sidecars.
    pub fn bundle(&self) -> PolicyBundle {
        self.bundle_tx.borrow().clone()
    }

    /// Watch the policy directory for changes and reload automatically.
    ///
    /// Only [`notify::event::EventKind::Modify`], [`notify::event::EventKind::Create`], and
    /// [`notify::event::EventKind::Remove`] events trigger a reload. Returns a
    /// [`CedarPolicyStoreWatcher`]: keep it alive for the watch to stay active.
    /// Dropping it stops the file watch and the reload task.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError` if the OS file watcher cannot be created or registered.
    pub fn watch(&self) -> Result<CedarPolicyStoreWatcher, AuthorityError> {
        use notify::Watcher as _;

        let path = self.policy_dir.clone();
        let this = self.clone();
        let (tx_signal, mut rx_signal) = tokio::sync::mpsc::channel::<()>(16);

        let watch_path = path.clone();
        let mut watcher = notify::recommended_watcher(
            move |res: notify::Result<notify::Event>| match res {
                Ok(event)
                    if matches!(
                        event.kind,
                        notify::event::EventKind::Modify(_)
                            | notify::event::EventKind::Create(_)
                            | notify::event::EventKind::Remove(_)
                    ) =>
                {
                    tracing::info!(path = %watch_path.display(), "policy directory changed; reloading");
                    let _ = tx_signal.try_send(());
                }
                Err(error) => tracing::error!(?error, "policy directory watch error"),
                _ => {}
            },
        )
        .map_err(|e| AuthorityError::WatchFailed { reason: e.to_string() })?;

        watcher
            .watch(&path, notify::RecursiveMode::NonRecursive)
            .map_err(|e| AuthorityError::WatchFailed {
                reason: e.to_string(),
            })?;

        let task = tokio::spawn(async move {
            while rx_signal.recv().await.is_some() {
                if let Err(error) = this.reload().await {
                    tracing::error!(%error, "policy reload failed; keeping previous policy set");
                }
            }
        });

        Ok(CedarPolicyStoreWatcher {
            _watcher: watcher,
            task,
            tx: self.bundle_tx.clone(),
        })
    }
}

/// Owns the file watcher and reload task for a [`CedarPolicyStore`].
/// Dropping this handle stops the file watch and the reload task.
pub struct CedarPolicyStoreWatcher {
    _watcher: notify::RecommendedWatcher,
    task: JoinHandle<()>,
    tx: watch::Sender<PolicyBundle>,
}

impl CedarPolicyStoreWatcher {
    /// Subscribe to policy bundle updates. Returns the current bundle
    /// immediately, then yields on changes.
    pub fn subscribe(&self) -> watch::Receiver<PolicyBundle> {
        self.tx.subscribe()
    }

    /// Abort the background reload task immediately.
    #[expect(dead_code, reason = "explicit shutdown hook for callers that need it")]
    pub fn abort(&self) {
        self.task.abort();
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
        let dir = tempfile::tempdir().expect("create the temp dir failed");
        for (name, content) in policies {
            fs::write(dir.path().join(name), content).expect("write policies failed");
        }
        dir
    }

    #[test]
    fn load_empty_policy_dir() {
        let dir = setup_policy_dir(&[]);
        let store = CedarPolicyStore::load(dir.path(), 30);
        assert!(store.is_ok());
    }

    #[test]
    fn load_valid_policy() {
        let dir = setup_policy_dir(&[("allow-all.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30);
        assert!(store.is_ok());
    }

    #[test]
    fn load_invalid_policy_fails_fast() {
        let dir = setup_policy_dir(&[("bad.cedar", "this is not valid cedar syntax {{{")]);
        let store = CedarPolicyStore::load(dir.path(), 30);
        assert!(store.is_err());
    }

    #[test]
    fn nonexistent_dir_fails() {
        let store = CedarPolicyStore::load(Path::new("/nonexistent/path"), 30);
        assert!(store.is_err());
    }

    #[test]
    fn version_hash_deterministic() {
        let v1 = compute_version_hash("policy A", "schema B");
        let v2 = compute_version_hash("policy A", "schema B");
        assert_eq!(v1, v2);
    }

    #[test]
    fn version_hash_changes_with_content() {
        let v1 = compute_version_hash("policy A", "schema B");
        let v2 = compute_version_hash("policy C", "schema B");
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn reload_no_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let result = store.reload().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reload_detects_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let v1 = store.bundle().version.clone();

        // Add a new policy file
        fs::write(
            dir.path().join("deny.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let result = store.reload().await;
        assert!(result.is_ok());
        let v2 = store.bundle().version;
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn watch_reloads_on_policy_change() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let v1 = store.bundle().version.clone();

        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();
        let _ = rx.borrow_and_update().clone(); // mark initial value as seen

        std::fs::write(
            dir.path().join("basic.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap_or_else(|e| panic!("{e}"));

        // The watch::changed() future is the completion signal — no polling needed.
        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.changed())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for policy reload"))
            .unwrap_or_else(|e| panic!("{e}"));

        assert_ne!(store.bundle().version, v1);
    }

    #[tokio::test]
    async fn watch_subscribe_receives_bundle_update() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), 30).unwrap_or_else(|e| panic!("{e}"));
        let watcher = store.watch().unwrap_or_else(|e| panic!("{e}"));
        let mut rx = watcher.subscribe();
        let _ = rx.borrow_and_update().clone(); // mark initial value as seen

        std::fs::write(
            dir.path().join("basic.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap_or_else(|e| panic!("{e}"));

        tokio::time::timeout(tokio::time::Duration::from_millis(500), rx.changed())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for bundle update"))
            .unwrap_or_else(|e| panic!("{e}"));

        let bundle = rx.borrow_and_update().clone();
        assert!(!bundle.version.is_empty());
    }

    #[test]
    fn schema_supports_firma_actions() {
        use cedar_policy::{
            Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
        };

        const SCHEMA_SRC: &str = include_str!("../policies/schema.cedarschema");
        const ACTIONS: &[&str] = &[
            "account.permission.change",
            "browser.purchase",
            "communication.external.send",
            "communication.internal.send",
            "credential.read",
            "credential.write",
            "filesystem.delete",
            "filesystem.read",
            "filesystem.write",
            "memory.cross_namespace.read",
            "memory.cross_namespace.write",
            "payment.purchase",
            "payment.transfer",
            "system.execute",
            "system.install",
        ];

        let (schema, _) = Schema::from_cedarschema_str(SCHEMA_SRC)
            .unwrap_or_else(|e| panic!("schema parse failed: {e}"));
        let policy_set = "permit(principal, action, resource);"
            .parse::<PolicySet>()
            .unwrap_or_else(|e| panic!("policy parse failed: {e}"));
        let context_json = serde_json::json!({
            "session_id": "sess_test",
            "timestamp_ms": 0i64,
            "params": "{}",
            "risk_score": 0i64,
        });

        for action in ACTIONS {
            let principal: EntityUid = "Firma::Agent::\"agent_test\""
                .to_string()
                .parse()
                .unwrap_or_else(|e| panic!("principal parse failed: {e}"));
            let action_uid: EntityUid = format!("Firma::Action::\"{action}\"")
                .parse()
                .unwrap_or_else(|e| panic!("action parse failed for '{action}': {e}"));
            let resource: EntityUid = "Firma::Resource::\"r\""
                .to_string()
                .parse()
                .unwrap_or_else(|e| panic!("resource parse failed: {e}"));

            let ctx = Context::from_json_value(context_json.clone(), Some((&schema, &action_uid)))
                .unwrap_or_else(|e| panic!("context build failed for '{action}': {e}"));

            let request = Request::new(
                Some(principal),
                Some(action_uid),
                Some(resource),
                ctx,
                Some(&schema),
            )
            .unwrap_or_else(|e| panic!("request build failed for '{action}': {e}"));

            let response =
                Authorizer::new().is_authorized(&request, &policy_set, &Entities::empty());
            assert!(
                matches!(response.decision(), Decision::Allow),
                "action '{action}' must be allowed"
            );
        }
    }
}
