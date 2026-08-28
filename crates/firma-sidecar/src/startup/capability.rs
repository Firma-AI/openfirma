//! Build the runtime [`CapabilityMap`] and [`TokenVerifier`] from the
//! sidecar's `[sidecar.capability_seed]` and
//! `[sidecar.authority].public_key_path` config.
//!
//! Each configured path contains canonical [`firma_core::CapabilitySeed`] TOML.
//! Before any read or watcher registration, the Sidecar resolves every path and
//! requires it to remain beneath the canonical runtime capabilities directory.
//! It then verifies every raw token and checks its signed claims against the
//! file before adding it to the runtime map.

use std::path::{Path, PathBuf};

use crate::config;
use crate::config::{CapabilitySeedConfig, SeedFile};
use crate::enforcement::capability_map::{CapabilityEntry, CapabilityMap};
use crate::enforcement::capability_validation::CapabilityMapHandle;
use anyhow::Context;
use firma_core::token::paseto::PasetoV4Verifier;
use firma_core::{CapabilityClaims, TokenError, TokenVerifier};
use firma_identifiers::{AgentId, SessionId};
use notify::Watcher as _;
use std::collections::HashSet;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

struct ResolvedSeedPath {
    configured_path: PathBuf,
    resolved_path: PathBuf,
    configured_parent: PathBuf,
}

fn resolve_seed_paths(
    seed: &CapabilitySeedConfig,
    capabilities_dir: &Path,
) -> anyhow::Result<Vec<ResolvedSeedPath>> {
    if seed.paths.is_empty() {
        return Ok(Vec::new());
    }

    let resolved_capabilities_dir = std::fs::canonicalize(capabilities_dir).with_context(|| {
        format!(
            "failed to resolve runtime capabilities directory '{}'",
            capabilities_dir.display()
        )
    })?;

    seed.paths
        .iter()
        .map(|configured_path| {
            let resolved_path = std::fs::canonicalize(configured_path).with_context(|| {
                format!(
                    "failed to resolve configured capability seed '{}'",
                    configured_path.display()
                )
            })?;
            if !resolved_path.starts_with(&resolved_capabilities_dir) {
                anyhow::bail!(
                    "capability seed '{}' resolves to '{}' and must be under the runtime \
                     capabilities directory '{}'",
                    configured_path.display(),
                    resolved_path.display(),
                    resolved_capabilities_dir.display()
                );
            }

            let configured_parent = configured_path.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "configured capability seed '{}' has no parent directory",
                    configured_path.display()
                )
            })?;
            let resolved_configured_parent = std::fs::canonicalize(configured_parent)
                .with_context(|| {
                    format!(
                        "failed to resolve parent '{}' of configured capability seed '{}'",
                        configured_parent.display(),
                        configured_path.display()
                    )
                })?;
            if !resolved_configured_parent.starts_with(&resolved_capabilities_dir) {
                anyhow::bail!(
                    "capability seed '{}' resolves to '{}', but its configured parent '{}' \
                     resolves to '{}' and must be under the runtime capabilities directory \
                     '{}'",
                    configured_path.display(),
                    resolved_path.display(),
                    configured_parent.display(),
                    resolved_configured_parent.display(),
                    resolved_capabilities_dir.display()
                );
            }

            Ok(ResolvedSeedPath {
                configured_path: configured_path.clone(),
                resolved_path,
                configured_parent: resolved_configured_parent,
            })
        })
        .collect()
}

/// Read every seed file referenced by `seed.paths` and assemble a
/// fully-indexed [`CapabilityMap`].
///
/// # Errors
///
/// Returns an error when the runtime directory or a seed path cannot be
/// resolved, a resolved seed is outside the runtime capabilities directory, a
/// seed file cannot be read or parsed, a seed cannot be converted into a
/// [`CapabilityClaims`] value, or its `raw_token` fails PASETO verification.
pub fn load_capability_map(
    seed: &CapabilitySeedConfig,
    verifier: &dyn TokenVerifier,
    capabilities_dir: &Path,
) -> anyhow::Result<CapabilityMap> {
    let mut entries: Vec<CapabilityEntry> = Vec::with_capacity(seed.paths.len());
    for resolved_seed in resolve_seed_paths(seed, capabilities_dir)? {
        let configured_path = resolved_seed.configured_path;
        let resolved_path = resolved_seed.resolved_path;
        let body = std::fs::read_to_string(&resolved_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to read capability seed '{}' resolved to '{}': {error}",
                configured_path.display(),
                resolved_path.display()
            )
        })?;
        let file: SeedFile = toml::from_str(&body).map_err(|_| {
            anyhow::anyhow!(
                "capability seed '{}' resolved to '{}' is not canonical CapabilitySeed TOML",
                configured_path.display(),
                resolved_path.display()
            )
        })?;
        entries.push(seed_into_entry(&file, verifier).map_err(|error| {
            anyhow::anyhow!(
                "invalid capability seed '{}' resolved to '{}': {error}",
                configured_path.display(),
                resolved_path.display()
            )
        })?);
    }
    Ok(CapabilityMap::new(entries))
}

/// Convert a parsed capability seed file into a runtime entry.
///
/// # Errors
///
/// Returns a descriptive error string when any identifier (token, agent, or
/// session) fails to parse or when the token fails verification.
pub fn seed_into_entry(
    file: &SeedFile,
    verifier: &dyn TokenVerifier,
) -> anyhow::Result<CapabilityEntry> {
    let seed_claims = seed_claims(file).context("invalid seed file")?;
    let verified_claims = verifier
        .verify(&file.raw_token)
        .context("raw_token failed PASETO verification")?;

    if seed_claims != verified_claims {
        anyhow::bail!("raw_token claims do not match seed claims");
    }

    Ok(CapabilityEntry {
        raw_token: file.raw_token.clone(),
        claims: verified_claims,
    })
}

fn seed_claims(file: &SeedFile) -> anyhow::Result<CapabilityClaims> {
    let agent_id: AgentId = file.agent_id.parse().context("invalid agent_id")?;
    let session_id: SessionId = file.session_id.parse().context("invalid session_id")?;

    Ok(CapabilityClaims {
        token_id: file.token_id,
        agent_id,
        session_id,
        action_set: file.action_set.clone(),
        resource_scope: file.resource_scope.clone(),
        issued_at: file.issued_at,
        expiry: file.expiry,
        context_hash: file.context_hash.clone(),
    })
}

/// Build the Stage 1 token verifier.
///
/// Returns a PASETO v4 verifier when `public_key_path` is set,
/// otherwise returns a reject-all verifier so unconfigured
/// deployments continue to deny every protected call.
///
/// # Errors
///
/// Returns an error when the public-key file cannot be read or its
/// contents do not match the Ed25519 32-byte format.
pub fn build_token_verifier(
    public_key_path: Option<&Path>,
) -> anyhow::Result<Box<dyn TokenVerifier + Send + Sync>> {
    if let Some(path) = public_key_path {
        let bytes = std::fs::read(path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read authority public key '{}': {e}",
                path.display()
            )
        })?;
        // PASETO's verifier has its own clock-skew leeway (10s by default).
        // Stage 1 already applies `clock_skew_tolerance` from config,
        // so we zero out the verifier's leeway to keep that knob authoritative
        // — otherwise the hard-coded 10s caps any operator setting above it.
        let verifier = PasetoV4Verifier::try_new(&bytes)
            .map(|v| v.with_leeway(chrono::Duration::zero()))
            .map_err(|e| {
                anyhow::anyhow!("invalid authority public key '{}': {e}", path.display())
            })?;
        Ok(Box::new(verifier))
    } else {
        Ok(Box::new(RejectAllVerifier))
    }
}

/// Default verifier used when no public key is configured. Always
/// returns [`TokenError::SignatureInvalid`] so Stage 1 stays
/// fail-closed.
struct RejectAllVerifier;

impl TokenVerifier for RejectAllVerifier {
    fn verify(&self, _raw_token: &str) -> Result<CapabilityClaims, TokenError> {
        Err(TokenError::SignatureInvalid {
            reason: "no authority public key configured".to_string(),
        })
    }
}

/// Owns the file watcher and reload task. Dropping it stops the watch and the
/// reload task.
pub struct CapabilityReloader {
    _watcher: notify::RecommendedWatcher,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CapabilityReloader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CapabilityReloader {
    /// Spawn the capability seed-file watcher.
    ///
    /// # Errors
    ///
    /// Returns an error when a seed's configured parent or resolved target is
    /// outside the runtime capabilities directory, or the OS file watcher
    /// cannot be created or registered.
    pub fn spawn(
        runtime_layout: &firma_runtime_state::RuntimeLayout,
        config: &config::CapabilitySeedConfig,
        token_verifier: Arc<dyn TokenVerifier + Send + Sync>,
        capability_handle: CapabilityMapHandle,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        let capabilities_dir = runtime_layout.capabilities_dir();
        let resolved_seed_paths = resolve_seed_paths(config, &capabilities_dir)?;
        let seed_config = config.clone();
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
                // Coalesced by the bounded channel; a full buffer already means a
                // reload is pending, so dropping the extra signal is harmless.
                let _ = tx_signal.try_send(());
            }
            Err(error) => tracing::error!(?error, "capability seed watch error"),
            _ => {}
        };

        let mut watcher = notify::recommended_watcher(event_handler)
            .context("failed to create capability seed watcher")?;

        // The seed is written via a temp-file + atomic rename into its parent
        // directory, so watch the parent directories (deduplicated) non-recursively
        // rather than the files themselves — the rename target may not exist yet.
        let mut watched_dirs = HashSet::new();
        for resolved_seed in &resolved_seed_paths {
            let resolved_parent = resolved_seed.resolved_path.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "resolved capability seed '{}' has no parent directory",
                    resolved_seed.resolved_path.display()
                )
            })?;
            for dir in [resolved_parent, resolved_seed.configured_parent.as_path()] {
                if watched_dirs.insert(dir.to_path_buf()) {
                    watcher
                        .watch(dir, notify::RecursiveMode::NonRecursive)
                        .with_context(|| {
                            format!(
                                "failed to watch capability seed directory '{}' for configured \
                                 seed '{}' resolved to '{}'",
                                dir.display(),
                                resolved_seed.configured_path.display(),
                                resolved_seed.resolved_path.display()
                            )
                        })?;
                }
            }
        }

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    recv = rx_signal.recv() => {
                        if recv.is_none() {
                            break;
                        }
                        // Drain coalesced signals so a burst of events triggers a
                        // single rebuild.
                        while rx_signal.try_recv().is_ok() {}

                        match load_capability_map(
                            &seed_config,
                            token_verifier.as_ref(),
                            &capabilities_dir,
                        ) {
                            Ok(map) => {
                                capability_handle.store(Arc::new(map));
                                tracing::info!(
                                    "capability map hot-reloaded from updated seed file(s)"
                                );
                            }
                            Err(error) => {
                                // Do not probe configured paths after resolution
                                // fails: they may no longer resolve inside the
                                // runtime boundary. Teardown deletion and invalid
                                // rewrites both retain the previous verified map.
                                tracing::error!(
                                    %error,
                                    "capability seed reload failed; keeping previous map \
                                     (it will fail closed on its own expiry)"
                                );
                            }
                        }
                    }
                }
            }
        });

        tracing::debug!(
            directories = watched_dirs.len(),
            "capability seed hot-reload watcher started"
        );
        Ok(Self {
            _watcher: watcher,
            task,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_core::TokenSigner;
    use firma_core::token::paseto::PasetoV4Signer;
    use firma_identifiers::TokenId;
    use pasetors::keys::{AsymmetricKeyPair, Generate};
    use pasetors::version4::V4;

    #[test]
    fn empty_seed_yields_empty_map() {
        let seed = CapabilitySeedConfig::default();
        let verifier = build_token_verifier(None).unwrap();
        let map = load_capability_map(
            &seed,
            verifier.as_ref(),
            Path::new("/directory/need/not/exist"),
        )
        .unwrap();
        // `CapabilityMap::select` returns `Err(EnforcementDecision)`
        // when no entry matches; the empty map must always deny.
        let result = map.select("sess", "communication.external.send", "wttr.in");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unreadable_path() {
        let temp = tempfile::tempdir().unwrap();
        let capabilities_dir = temp.path().join("capabilities");
        std::fs::create_dir(&capabilities_dir).unwrap();
        let seed = CapabilitySeedConfig {
            paths: vec![capabilities_dir.join("definitely-not-here.toml")],
            hot_reload: true,
        };
        let verifier = build_token_verifier(None).unwrap();
        let err = load_capability_map(&seed, verifier.as_ref(), &capabilities_dir)
            .unwrap_err()
            .to_string();
        assert!(err.contains("definitely-not-here.toml"));
    }

    #[test]
    fn unconfigured_verifier_denies_every_token() {
        let verifier = build_token_verifier(None).unwrap();
        let err = verifier
            .verify("v4.public.anything")
            .expect_err("RejectAllVerifier must always deny");
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn seed_load_rejects_unverified_raw_token() {
        let (_sk, pk) = generate_keypair();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let claims = sample_claims();
        let mut file = seed_file_from_claims(&claims);
        file.raw_token = "v4.public.not-a-real-token".to_string();

        let err = seed_into_entry(&file, &verifier).unwrap_err();

        assert!(
            err.to_string()
                .contains("raw_token failed PASETO verification")
        );
    }

    #[test]
    fn seed_load_rejects_claims_that_do_not_match_raw_token() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let claims = sample_claims();
        let raw_token = signer.sign(&claims).unwrap();
        let mut file = seed_file_from_claims(&claims);
        file.raw_token = raw_token;
        file.action_set = vec!["github.repo.write".to_string()];

        let err = seed_into_entry(&file, &verifier).unwrap_err();
        let err = err.to_string();

        assert!(err.contains("raw_token claims do not match seed claims"));
    }

    #[test]
    fn seed_load_uses_verified_token_claims() {
        let (sk, pk) = generate_keypair();
        let signer = PasetoV4Signer::try_new(&sk).unwrap();
        let verifier = PasetoV4Verifier::try_new(&pk).unwrap();
        let claims = sample_claims();
        let raw_token = signer.sign(&claims).unwrap();
        let mut file = seed_file_from_claims(&claims);
        file.raw_token = raw_token.clone();

        let entry = seed_into_entry(&file, &verifier).unwrap();

        assert_eq!(entry.raw_token, raw_token);
        assert_eq!(entry.claims, claims);
    }

    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        (kp.secret.as_bytes().to_vec(), kp.public.as_bytes().to_vec())
    }

    fn sample_claims() -> CapabilityClaims {
        let now = chrono::Utc::now();
        CapabilityClaims {
            token_id: TokenId::generate(),
            agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
            session_id: "sess_xyz".parse().unwrap(),
            action_set: vec!["communication.external.send".to_string()],
            resource_scope: "https://api.example.com/*".to_string(),
            issued_at: now,
            expiry: now + chrono::Duration::minutes(10),
            context_hash: "abcdef1234567890".to_string(),
        }
    }

    fn seed_file_from_claims(claims: &CapabilityClaims) -> SeedFile {
        SeedFile {
            raw_token: String::new(),
            token_id: claims.token_id,
            agent_id: claims.agent_id.to_string(),
            session_id: claims.session_id.to_string(),
            action_set: claims.action_set.clone(),
            resource_scope: claims.resource_scope.clone(),
            issued_at: claims.issued_at,
            expiry: claims.expiry,
            context_hash: claims.context_hash.clone(),
        }
    }
}
