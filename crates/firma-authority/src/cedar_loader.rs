use std::num::NonZeroU32;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use cedar_policy::{PolicySet, Schema};
use firma_core::cedar::PolicyFiles;
use sha2::{Digest, Sha256};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;

use firma_protobuf::v1::{ActionMappingSnapshot, PolicyBundle};
use prost::Message as _;

/// Canonical Firma enforcement schema, re-exported from `firma-core`.
///
/// Used as the default schema when no explicit `schema_path` is configured.
/// Overriding is intentional — operators who extend the action registry
/// can set `schema_path` in the authority config to point to their custom
/// `.cedarschema` or `.json` file.
const DEFAULT_SCHEMA: &str = firma_core::cedar::FIRMA_SCHEMA;

/// Quiet period after a watched change before inputs are read.
const RELOAD_SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

/// All mutable policy state kept under a single lock for atomic swaps.
#[derive(Clone)]
pub struct PolicyState {
    pub(crate) policy_set: Arc<PolicySet>,
    pub(crate) schema: Arc<Schema>,
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
    bundle_ttl_seconds: NonZeroU32,
    /// Authored mapping inputs; `None` for a policy-only store.
    mapping_paths: Option<Vec<PathBuf>>,
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
        bundle_ttl_seconds: NonZeroU32,
    ) -> Result<Self> {
        Self::load_inner(policy_dir, schema_path, bundle_ttl_seconds, None)
    }

    /// Load one complete enforcement generation from policies and mapping files.
    ///
    /// # Errors
    /// Returns an error if policy, schema, or mapping validation fails.
    pub fn load_with_mappings(
        policy_dir: &Path,
        schema_path: Option<PathBuf>,
        bundle_ttl_seconds: NonZeroU32,
        mapping_paths: Vec<PathBuf>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !mapping_paths.is_empty(),
            "authority.mapping_rules_paths must contain at least one mapping file"
        );
        for (index, path) in mapping_paths.iter().enumerate() {
            anyhow::ensure!(
                !path.as_os_str().is_empty(),
                "authority.mapping_rules_paths[{index}] must not be empty"
            );
        }
        Self::load_inner(
            policy_dir,
            schema_path,
            bundle_ttl_seconds,
            Some(mapping_paths),
        )
    }

    /// `mapping_paths` is `None` for a policy-only store, such as the issuance
    /// store, whose bundle is never streamed and so carries no mappings.
    fn load_inner(
        policy_dir: &Path,
        schema_path: Option<PathBuf>,
        bundle_ttl_seconds: NonZeroU32,
        mapping_paths: Option<Vec<PathBuf>>,
    ) -> Result<Self> {
        let (policies, policy_set) = read_policies(policy_dir)?;
        let (schema_src, schema) = read_schema(schema_path.as_deref())?;

        firma_core::validate_policies(&policy_set, &schema, Some(&policies))?;

        let policies_src = policies.concat();
        let mappings = mapping_paths
            .as_deref()
            .map(crate::mappings::load)
            .transpose()?;
        let version = snapshot_version(&policies_src, &schema_src, mappings.as_ref());
        let bundle = PolicyBundle {
            version,
            policies: policies_src.into_bytes(),
            entity_schema: schema_src.into_bytes(),
            ttl_seconds: bundle_ttl_seconds.get(),
            mappings,
        };
        validate_bundle_size(&bundle)?;

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
            mapping_paths,
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
        let mappings = self
            .mapping_paths
            .as_deref()
            .map(crate::mappings::load)
            .transpose()?;
        let new_version = snapshot_version(&policies_src, &schema_src, mappings.as_ref());

        let new_bundle = PolicyBundle {
            version: new_version.clone(),
            policies: policies_src.into_bytes(),
            entity_schema: schema_src.into_bytes(),
            ttl_seconds: self.bundle_ttl_seconds.get(),
            mappings,
        };
        validate_bundle_size(&new_bundle)?;
        let new_policy_set = Arc::new(new_policy_set);
        let new_schema = Arc::new(new_schema);
        {
            let mut state = self.state.write().await;
            if self.bundle_tx.borrow().version == new_version {
                tracing::debug!("policy reload: no changes detected");
                return Ok(());
            }

            state.policy_set = new_policy_set;
            state.schema = new_schema;
            // Serialize publication with the state swap and version recheck.
            self.bundle_tx.send_replace(new_bundle);
            drop(state);
        }

        tracing::info!(version = %new_version, "cedar policies reloaded");
        Ok(())
    }

    /// Get a snapshot of the current policy set and schema for evaluation.
    pub(crate) async fn snapshot(&self) -> PolicyState {
        self.state.read().await.clone()
    }

    /// Get the current policy bundle for distribution to sidecars.
    #[must_use]
    pub(crate) fn bundle(&self) -> PolicyBundle {
        self.bundle_tx.borrow().clone()
    }

    /// Watch the enforcement inputs for changes and reload automatically.
    ///
    /// The policy directory is watched recursively and any change beneath it
    /// triggers a reload. The schema and mapping files are watched through
    /// their parent directories and the parents of symlinks on any input's
    /// path, where only events naming a configured input, or a change to the
    /// path an input resolves to, trigger a reload (see
    /// [`crate::input_watch`]). Only [`notify::event::EventKind::Modify`],
    /// [`notify::event::EventKind::Create`], and
    /// [`notify::event::EventKind::Remove`] events count. Bursts of events, such
    /// as a truncate followed by a write, are coalesced into one reload. Returns
    /// a [`CedarPolicyStoreWatcher`]: keep it alive for the watch to stay
    /// active. Dropping it stops the file watch and the reload task.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS file watcher cannot be created or registered.
    pub(crate) fn watch(self) -> Result<CedarPolicyStoreWatcher> {
        use notify::Watcher as _;

        let path = self.policy_dir.clone();
        let this = self.clone();
        let files = || {
            self.schema_path
                .iter()
                .chain(self.mapping_paths.iter().flatten())
                .map(PathBuf::as_path)
        };
        let mut inputs = crate::input_watch::WatchedInputs::new(&path, files());
        let (tx_signal, mut rx_signal) = tokio::sync::mpsc::channel::<()>(1);

        let event_handler = move |res: notify::Result<notify::Event>| match res {
            Ok(event)
                if matches!(
                    event.kind,
                    notify::event::EventKind::Modify(_)
                        | notify::event::EventKind::Create(_)
                        | notify::event::EventKind::Remove(_)
                ) =>
            {
                let changed = event.paths.iter().find(|path| inputs.contains(path));
                // Retargeting a symlink creates, removes, or renames an entry;
                // content and metadata writes, such as log appends, cannot.
                let relinks = !matches!(
                    event.kind,
                    notify::event::EventKind::Modify(
                        notify::event::ModifyKind::Data(_) | notify::event::ModifyKind::Metadata(_)
                    )
                );
                if changed.is_some() || (relinks && inputs.retargeted()) {
                    // Debug, not info: a log file in a watched directory would
                    // otherwise turn each trigger line into the next event.
                    let path = changed.or_else(|| event.paths.first());
                    tracing::debug!(path = ?path, "hot-reload triggered by file change");
                    let _ = tx_signal.try_send(());
                }
            }
            Err(error) => tracing::error!(?error, "policy watch error"),
            _ => {}
        };

        let mut watcher = notify::recommended_watcher(event_handler)
            .context("failed to create policy watcher")?;
        watcher
            .watch(&path, notify::RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch policy directory {}", path.display()))?;
        // Parent watches survive editors replacing a single-file input by rename.
        for parent in crate::input_watch::WatchedInputs::file_parents(&path, files()) {
            watcher
                .watch(&parent, notify::RecursiveMode::NonRecursive)
                .with_context(|| format!("failed to watch input directory {}", parent.display()))?;
        }

        let task = tokio::spawn(async move {
            while rx_signal.recv().await.is_some() {
                // Let a burst of writes settle so a partially written input is
                // not published as its own generation.
                tokio::time::sleep(RELOAD_SETTLE).await;
                while rx_signal.try_recv().is_ok() {}
                if let Err(error) = this.reload().await {
                    tracing::error!(error = %format!("{error:#}"), "enforcement reload failed; keeping previous snapshot");
                }
            }
        });

        let tx = self.bundle_tx.clone();
        Ok(CedarPolicyStoreWatcher {
            _watcher: watcher,
            _task: task,
            store: self,
            tx,
        })
    }
}

/// Owns the file watcher and reload task for a [`CedarPolicyStore`].
/// Dropping this handle stops the file watch and the reload task.
pub struct CedarPolicyStoreWatcher {
    _watcher: notify::RecommendedWatcher,
    _task: JoinHandle<()>,
    store: CedarPolicyStore,
    tx: watch::Sender<PolicyBundle>,
}

impl CedarPolicyStoreWatcher {
    /// Subscribe to policy bundle updates. Returns the current bundle
    /// immediately, then yields on changes.
    #[must_use]
    pub(crate) fn subscribe(&self) -> watch::Receiver<PolicyBundle> {
        self.tx.subscribe()
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

/// SHA-256 version of one generation: length-prefixed policy and schema
/// sources, then the encoded mapping snapshot when the store carries one.
fn snapshot_version(
    policies: &str,
    schema: &str,
    mappings: Option<&ActionMappingSnapshot>,
) -> String {
    let mut hasher = Sha256::new();
    for bytes in [policies.as_bytes(), schema.as_bytes()] {
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(bytes);
    }
    if let Some(mappings) = mappings {
        hasher.update(mappings.encode_to_vec());
    }
    hex::encode(hasher.finalize())
}

fn validate_bundle_size(bundle: &PolicyBundle) -> Result<()> {
    // Budget the full stream message, including a maximal encoded timestamp.
    // This mirrors the Sidecar receive ceiling without coupling the producer to it.
    let timestamp_update = firma_protobuf::v1::PolicyBundleUpdate {
        bundle: None,
        updated_at: Some(prost_types::Timestamp {
            seconds: i64::MIN,
            nanos: i32::MIN,
        }),
        policy_set: None,
    };
    let bundle_len = bundle.encoded_len();
    let update_len = prost::encoding::key_len(1)
        + prost::encoding::encoded_len_varint(bundle_len as u64)
        + bundle_len
        + timestamp_update.encoded_len();
    anyhow::ensure!(
        update_len <= 16 * 1024 * 1024,
        "enforcement snapshot exceeds the 16 MiB stream limit"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const BUNDLE_TTL: NonZeroU32 = NonZeroU32::new(30).unwrap();

    /// Build a valid `EnforcementContext` JSON matching the canonical schema.
    /// Centralized so all context-validation tests share one source of truth
    /// and stay in sync when fields are added.
    #[must_use]
    fn valid_context_json(
        session_id: &str,
        timestamp_ms: i64,
        session_duration_s: i64,
        action_count: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "session_id": session_id,
            "timestamp_ms": timestamp_ms,
            "params": "{}",
            "risk_score": 0i64,
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
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL);
        assert!(store.is_ok());
    }

    #[test]
    fn load_valid_policy() {
        let dir = setup_policy_dir(&[("allow-all.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL);
        assert!(store.is_ok());
    }

    #[test]
    fn load_invalid_policy_fails_fast() {
        let dir = setup_policy_dir(&[("bad.cedar", "this is not valid cedar syntax {{{")]);
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL);
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
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL);
        assert!(store.is_err());
    }

    #[test]
    fn nonexistent_dir_fails() {
        let store = CedarPolicyStore::load(Path::new("/nonexistent/path"), None, BUNDLE_TTL);
        assert!(store.is_err());
    }

    #[test]
    fn version_hash_deterministic() {
        let v1 = snapshot_version("policy A", "schema B", None);
        let v2 = snapshot_version("policy A", "schema B", None);
        assert_eq!(v1, v2);
    }

    #[test]
    fn version_hash_changes_with_content() {
        let v1 = snapshot_version("policy A", "schema B", None);
        let v2 = snapshot_version("policy C", "schema B", None);
        assert_ne!(v1, v2);
    }

    #[tokio::test]
    async fn reload_no_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL).unwrap();
        let result = store.reload().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn reload_detects_changes() {
        let dir = setup_policy_dir(&[("basic.cedar", "permit(principal, action, resource);")]);
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL).unwrap();
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
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL).unwrap();
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
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL).unwrap();
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
        let store = CedarPolicyStore::load(dir.path(), None, BUNDLE_TTL).unwrap();
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
        assert_ne!(bundle.version, "");
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
        let store = CedarPolicyStore::load(dir.path(), Some(schema_path.clone()), BUNDLE_TTL)
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

        let store = CedarPolicyStore::load(dir.path(), Some(schema_path.clone()), BUNDLE_TTL)
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
        let context_json = valid_context_json("sess_test", 0, 42, 3);
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
        let context_json = valid_context_json("sess_test", 0, 0, 0);

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
