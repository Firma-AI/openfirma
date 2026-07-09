use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use cedar_policy::{PolicySet, Schema};
use firma_core::cedar::PolicyFiles;
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

use firma_core::policy::PolicyBundle;

/// Canonical Firma enforcement schema, re-exported from `firma-core`.
///
/// Used as the default schema when no explicit `schema_path` is configured.
/// Overriding is intentional — operators who extend the action registry
/// can set `schema_path` in the authority config to point to their custom
/// `.cedarschema` or `.json` file.
pub(crate) const DEFAULT_SCHEMA: &str = firma_core::cedar::FIRMA_SCHEMA;

/// All mutable policy state kept under a single lock for atomic swaps.
struct PolicyState {
    policy_set: Arc<PolicySet>,
    schema: Arc<Schema>,
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
    /// Policy directory path (`.cedar` files).
    policy_dir: PathBuf,
    /// Explicit schema path override. When `None`, falls back to [`DEFAULT_SCHEMA`].
    schema_path: Option<PathBuf>,
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
    /// Returns an error if the policy directory cannot be read or
    /// any `.cedar` file contains invalid syntax.
    pub fn load(
        policy_dir: &Path,
        schema_path: Option<PathBuf>,
        bundle_ttl_seconds: u32,
    ) -> Result<Self> {
        let (policies, policy_set) = read_policies(policy_dir)?;
        let (schema_src, schema) = read_schema(schema_path.as_deref())?;

        firma_core::validate_policies(&policy_set, &schema, Some(&policies))?;

        let policies_src = policies.concat();
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
                schema: Arc::new(schema),
            })),
            bundle_tx,
            policy_dir: policy_dir.to_path_buf(),
            schema_path,
            bundle_ttl_seconds,
        })
    }

    /// Reload policies from disk, atomically swapping all state in one lock
    /// acquisition. If the new policy set is invalid, keeps the previous set
    /// (FR-2). No-ops if the version hash has not changed.
    async fn reload(&self) -> Result<()> {
        let (policies, new_policy_set) = read_policies(&self.policy_dir)?;
        let (schema_src, new_schema) = read_schema(self.schema_path.as_deref())?;

        firma_core::validate_policies(&new_policy_set, &new_schema, Some(&policies))?;

        let policies_src = policies.concat();
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
            state.schema = Arc::new(new_schema);
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

    /// Get the current schema snapshot for evaluation.
    pub async fn schema(&self) -> Arc<Schema> {
        self.state.read().await.schema.clone()
    }

    /// Get the current policy bundle for distribution to sidecars.
    #[must_use]
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
    /// Returns an error if the OS file watcher cannot be created or registered.
    pub fn watch(self) -> Result<CedarPolicyStoreWatcher> {
        use notify::Watcher as _;

        let path = self.policy_dir.clone();
        let schema_path = self.schema_path.clone();
        let this = self.clone();
        let (tx_signal, mut rx_signal) = tokio::sync::mpsc::channel::<()>(16);

        let event_handler = move |res: notify::Result<notify::Event>| match res {
            Ok(event)
                if matches!(
                    event.kind,
                    notify::event::EventKind::Modify(_)
                        | notify::event::EventKind::Create(_)
                        | notify::event::EventKind::Remove(_)
                ) =>
            {
                if let Some(p) = event.paths.first() {
                    tracing::info!(path = %p.display(), "hot-reload triggered by file change");
                } else {
                    tracing::info!("hot-reload triggered");
                }
                let _ = tx_signal.try_send(());
            }
            Err(error) => tracing::error!(?error, "policy watch error"),
            _ => {}
        };

        let mut watcher = notify::recommended_watcher(event_handler)
            .context("failed to create policy watcher")?;
        watcher
            .watch(&path, notify::RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch policy directory {}", path.display()))?;

        if let Some(ref sp) = schema_path {
            // Watch the schema file explicitly. If it is inside the policy directory,
            // notify handles the overlap on most platforms; if outside, this is required.
            if !sp.starts_with(&path) {
                watcher
                    .watch(sp, notify::RecursiveMode::NonRecursive)
                    .with_context(|| format!("failed to watch schema file {}", sp.display()))?;
            }
        }

        let task = tokio::spawn(async move {
            while rx_signal.recv().await.is_some() {
                if let Err(error) = this.reload().await {
                    tracing::error!(%error, "policy reload failed; keeping previous policy set");
                }
            }
        });

        let tx = self.bundle_tx.clone();
        Ok(CedarPolicyStoreWatcher {
            _watcher: watcher,
            task,
            store: self,
            tx,
        })
    }
}

/// Owns the file watcher and reload task for a [`CedarPolicyStore`].
/// Dropping this handle stops the file watch and the reload task.
pub struct CedarPolicyStoreWatcher {
    _watcher: notify::RecommendedWatcher,
    task: JoinHandle<()>,
    store: CedarPolicyStore,
    tx: watch::Sender<PolicyBundle>,
}

impl CedarPolicyStoreWatcher {
    /// Subscribe to policy bundle updates. Returns the current bundle
    /// immediately, then yields on changes.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<PolicyBundle> {
        self.tx.subscribe()
    }

    /// Abort the background reload task immediately.
    pub fn abort(&self) {
        self.task.abort();
    }
}

impl Deref for CedarPolicyStoreWatcher {
    type Target = CedarPolicyStore;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}

/// Read all `.cedar` files from a directory and concatenate their contents.
fn read_policies(policy_dir: &Path) -> Result<(PolicyFiles, PolicySet)> {
    if !policy_dir.is_dir() {
        bail!("policy directory does not exist: {}", policy_dir.display());
    }

    let mut policies = PolicyFiles::default();
    let mut entries: Vec<_> = std::fs::read_dir(policy_dir)
        .with_context(|| format!("cannot read policy directory {}", policy_dir.display()))?
        .filter_map(Result::ok)
        .collect();

    // Sort for deterministic ordering
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in &entries {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "cedar") {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("cannot read {}", path.display()))?;

            policies.push(path, content);
        }
    }

    let parsed = if policies.is_empty() {
        PolicySet::new()
    } else {
        policies
            .concat()
            .parse::<PolicySet>()
            .map_err(anyhow::Error::from)
            .context("cedar policy parse error")?
    };

    Ok((policies, parsed))
}

/// Read Cedar schema using the resolution order:
///   1. `schema_path` if explicitly provided
///   2. [`DEFAULT_SCHEMA`] (embedded canonical schema)
fn read_schema(schema_path: Option<&Path>) -> Result<(String, Schema)> {
    let schema_src = if let Some(path) = schema_path {
        std::fs::read_to_string(path)
            .with_context(|| format!("cannot read schema {}", path.display()))?
    } else {
        DEFAULT_SCHEMA.to_string()
    };

    let (schema, warnings) = Schema::from_cedarschema_str(&schema_src)
        .map_err(anyhow::Error::from)
        .context("cedar schema parse error")?;
    for w in warnings {
        tracing::warn!(%w, "cedar schema warning");
    }

    Ok((schema_src, schema))
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
mod tests {
    use super::*;
    use std::fs;

    /// Build a valid `EnforcementContext` JSON matching the canonical schema.
    /// Centralized so all context-validation tests share one source of truth
    /// and stay in sync when fields are added.
    #[must_use]
    fn valid_context_json(
        session_id: &str,
        timestamp_ms: i64,
        budget_remaining: i64,
        session_duration_s: i64,
        action_count: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "session_id": session_id,
            "timestamp_ms": timestamp_ms,
            "params": "{}",
            "risk_score": 0i64,
            "budget_remaining": budget_remaining,
            "session_duration_s": session_duration_s,
            "action_count": action_count,
            "raw_transport": "https",
            "deny_count": 0i64,
            "prior_action_classes": [],
            "last_resource": "",
            "transfer_amount": 0i64,
            "daily_cumulative_amount": 0i64,
            "transfers_last_10m": 0i64,
            "same_payee_count_30m": 0i64,
            "session_transfer_count": 0i64,
        })
    }

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
        let store = CedarPolicyStore::load(dir.path(), None, 30);
        assert!(store.is_ok());
    }

    #[test]
    fn load_valid_policy() {
        let dir = setup_policy_dir(&[("allow-all.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, 30);
        assert!(store.is_ok());
    }

    #[test]
    fn load_invalid_policy_fails_fast() {
        let dir = setup_policy_dir(&[("bad.cedar", "this is not valid cedar syntax {{{")]);
        let store = CedarPolicyStore::load(dir.path(), None, 30);
        assert!(store.is_err());
    }

    #[test]
    fn load_schema_invalid_policy_fails() {
        // Parses fine, but `foo.bar` is not in the Firma schema, so strict
        // validation rejects it. Authority load must fail closed.
        let dir = setup_policy_dir(&[(
            "bad.cedar",
            "forbid(principal, action == Firma::Action::\"foo.bar\", resource);",
        )]);
        let store = CedarPolicyStore::load(dir.path(), None, 30);
        assert!(store.is_err());
    }

    #[test]
    fn nonexistent_dir_fails() {
        let store = CedarPolicyStore::load(Path::new("/nonexistent/path"), None, 30);
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
        let store = CedarPolicyStore::load(dir.path(), None, 30).unwrap();
        let result = store.reload().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reload_detects_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, 30).unwrap();
        let v1 = store.bundle().version.clone();

        // Add a new policy file
        fs::write(
            dir.path().join("deny.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap();

        let result = store.reload().await;
        assert!(result.is_ok());
        let v2 = store.bundle().version;
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn reload_schema_invalid_keeps_previous_bundle() {
        // Start from a valid bundle, then introduce a schema-invalid policy
        // (`foo.bar` is not in the Firma schema). reload must fail closed
        // and keep the previously loaded bundle.
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, 30).unwrap();
        let v1 = store.bundle().version.clone();

        fs::write(
            dir.path().join("bad.cedar"),
            "forbid(principal, action == Firma::Action::\"foo.bar\", resource);",
        )
        .unwrap();

        let result = store.reload().await;
        assert!(result.is_err(), "schema-invalid reload must fail");
        assert_eq!(
            store.bundle().version,
            v1,
            "previous bundle must be retained after a failed reload"
        );
    }

    #[tokio::test]
    async fn watch_reloads_on_policy_change() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, 30).unwrap();
        let v1 = store.bundle().version.clone();

        let store = store.watch().unwrap();
        let mut rx = store.subscribe();
        let _ = rx.borrow_and_update().clone(); // mark initial value as seen
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        std::fs::write(
            dir.path().join("deny.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), rx.changed())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for policy reload"))
            .unwrap();

        assert_ne!(store.bundle().version, v1);
    }

    #[tokio::test]
    async fn watch_subscribe_receives_bundle_update() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, 30).unwrap();
        let watcher = store.watch().unwrap();
        let mut rx = watcher.subscribe();
        let initial_bundle = rx.borrow_and_update().clone();
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        std::fs::write(
            dir.path().join("deny.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), rx.changed())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for bundle update"))
            .unwrap();

        let bundle = rx.borrow().clone();
        assert!(!bundle.version.is_empty());
        assert_ne!(bundle.version, initial_bundle.version);
    }

    #[tokio::test]
    async fn watch_reloads_on_schema_change() {
        // Now requires explicit schema_path to use a local file.
        let dir = setup_policy_dir(&[
            ("basic.cedar", "permit(principal, action, resource);"),
            ("schema.cedarschema", DEFAULT_SCHEMA),
        ]);
        let schema_path = dir.path().join("schema.cedarschema");
        let store = CedarPolicyStore::load(dir.path(), Some(schema_path.clone()), 30)
            .unwrap()
            .watch()
            .unwrap();
        let v1 = store.bundle().version.clone();
        let mut rx = store.subscribe();
        let _ = rx.borrow_and_update().clone();
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        // Append a comment — schema bytes change, version hash must change.
        let mut schema_src = fs::read_to_string(&schema_path).unwrap();
        schema_src.push_str("\n// updated");
        fs::write(&schema_path, &schema_src).unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), rx.changed())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for schema reload"))
            .unwrap();

        assert_ne!(store.bundle().version, v1);
    }

    #[tokio::test]
    async fn watch_reloads_on_external_schema_change() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let schema_dir = tempfile::tempdir().unwrap();
        let schema_path = schema_dir.path().join("external.cedarschema");
        fs::write(&schema_path, DEFAULT_SCHEMA).unwrap();

        let store = CedarPolicyStore::load(dir.path(), Some(schema_path.clone()), 30)
            .unwrap()
            .watch()
            .unwrap();
        let v1 = store.bundle().version.clone();

        let mut rx = store.subscribe();
        let _ = rx.borrow_and_update().clone();
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        // Modify external schema
        let mut schema_src = fs::read_to_string(&schema_path).unwrap();
        schema_src.push_str("\n// external update");
        fs::write(&schema_path, &schema_src).unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), rx.changed())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for external schema reload"))
            .unwrap();

        assert_ne!(store.bundle().version, v1);
    }

    #[test]
    fn extended_enforcement_context_parses() {
        use cedar_policy::{Context, EntityUid, Schema};

        const SCHEMA_SRC: &str = DEFAULT_SCHEMA;
        let (schema, _) = Schema::from_cedarschema_str(SCHEMA_SRC)
            .unwrap_or_else(|e| panic!("schema parse failed: {e}"));
        let action_uid: EntityUid = "Firma::Action::\"communication.external.send\""
            .parse()
            .unwrap_or_else(|e| panic!("action parse: {e}"));
        let context_json = valid_context_json("sess_test", 0, 1000, 42, 3);
        Context::from_json_value(context_json, Some((&schema, &action_uid)))
            .unwrap_or_else(|e| panic!("context validation failed: {e}"));
    }

    #[test]
    fn schema_supports_firma_actions() {
        use cedar_policy::{
            Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
        };

        const SCHEMA_SRC: &str = DEFAULT_SCHEMA;
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
        let context_json = valid_context_json("sess_test", 0, i64::MAX, 0, 0);

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
