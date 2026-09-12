//! The environment one `firma run` launch imposes on the wrapped process.
//!
//! Assembling that environment is a sequence of overlapping groups — host
//! passthrough, profile settings, run identity, Sidecar endpoint, trust anchor,
//! network overrides, attribution, capability material. Several of them name the
//! same variables on purpose, so the order they are applied in is a contract
//! rather than an implementation detail: the last group to set a key wins.
//!
//! [`ExecutionEnv`] owns that map. [`ExecutionEnv::new`] applies the groups
//! every launch has — profile settings, run identity, Sidecar endpoint — and
//! the remaining `with_*` methods layer the situational ones on top, so the
//! precedence chain is readable at the call site instead of being implied by
//! statement order inside one long function.

use std::collections::btree_map;
use std::collections::{BTreeMap, BTreeSet};

use crate::config::{CapabilitySource, ResolvedProfile, SidecarEndpoint};
use crate::identity::RunIdentity;
use crate::trust::SidecarTrustAnchor;

/// Environment variables handed to the wrapped process for one launch.
///
/// Start from [`ExecutionEnv::new`], then chain the `with_*` methods in
/// precedence order, lowest priority first. Each one overwrites keys set
/// before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionEnv {
    vars: BTreeMap<String, String>,
}

impl ExecutionEnv {
    /// Apply the groups no launch can omit: the profile's host passthrough and
    /// `env_set`, this run's identity, and the Sidecar endpoint the wrapped
    /// process must reach.
    ///
    /// `sidecar_endpoint` is passed separately from `profile` because autostart
    /// may substitute a per-run socket for the endpoint the profile resolved to.
    ///
    /// Identity is applied after the profile's own settings, so neither a host
    /// variable nor a profile setting can spoof the agent, session, or profile
    /// this run is attributed to.
    #[must_use]
    pub(crate) fn new(
        profile: &ResolvedProfile,
        identity: &RunIdentity,
        sidecar_endpoint: &SidecarEndpoint,
    ) -> Self {
        Self::default()
            .with_passthrough(&profile.env_passthrough)
            .with_profile_overrides(&profile.env_set)
            .with_identity(identity)
            .with_attribution(identity)
            .with_sidecar_endpoint(sidecar_endpoint)
    }

    /// Copy the named variables from the host environment, skipping any that
    /// are unset.
    #[must_use]
    fn with_passthrough(mut self, keys: &BTreeSet<String>) -> Self {
        for key in keys {
            if let Ok(value) = std::env::var(key) {
                self.vars.insert(key.clone(), value);
            }
        }
        self
    }

    /// Apply the profile's explicit `env_set` values.
    #[must_use]
    fn with_profile_overrides(mut self, overrides: &BTreeMap<String, String>) -> Self {
        self.vars.extend(overrides.clone());
        self
    }

    /// Publish this run's sandbox, session, agent, and profile identity.
    #[must_use]
    fn with_identity(mut self, identity: &RunIdentity) -> Self {
        self.vars.extend(identity.env_pairs());
        self
    }

    /// Point the wrapped process at the Sidecar.
    ///
    /// A TCP endpoint becomes the proxy variables every HTTP ecosystem reads; a
    /// Unix endpoint becomes the socket path, because a Unix socket cannot be
    /// spelled as a proxy URL.
    #[must_use]
    fn with_sidecar_endpoint(mut self, endpoint: &SidecarEndpoint) -> Self {
        match endpoint {
            SidecarEndpoint::Tcp { addr } => {
                let proxy = format!("http://{addr}");
                for key in [
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "http_proxy",
                    "https_proxy",
                    "ALL_PROXY",
                    "all_proxy",
                ] {
                    self.vars.insert(key.to_string(), proxy.clone());
                }
            }
            SidecarEndpoint::Unix { path } => {
                self.vars.insert(
                    "FIRMA_SIDECAR_UNIX_SOCKET".to_string(),
                    path.display().to_string(),
                );
            }
        }
        self
    }

    /// Name the CA file this launch trusts, when the Sidecar publishes one.
    ///
    /// Applied after passthrough and profile settings so a host `SSL_CERT_FILE`
    /// cannot leave the wrapped process trusting the host's roots while the
    /// Sidecar terminates TLS.
    #[must_use]
    pub(crate) fn with_trust_anchor(mut self, anchor: Option<&SidecarTrustAnchor>) -> Self {
        if let Some(anchor) = anchor {
            anchor.inject_trust_env(&mut self.vars);
        }
        self
    }

    /// Apply the environment an autostarted Sidecar reported for itself.
    #[must_use]
    pub(crate) fn with_network_overrides(mut self, overrides: &BTreeMap<String, String>) -> Self {
        self.vars.extend(overrides.clone());
        self
    }

    /// Carry this run's attribution headers as one JSON payload for transport
    /// bridges.
    ///
    /// Serialization cannot fail for a string map; an empty object is a safe
    /// floor if it ever does.
    #[must_use]
    fn with_attribution(mut self, identity: &RunIdentity) -> Self {
        self.vars.insert(
            "FIRMA_RUN_ATTR_HEADERS_JSON".to_string(),
            serde_json::to_string(&identity.full_attribution_headers())
                .unwrap_or_else(|_| "{}".to_string()),
        );
        self
    }

    /// Hand the wrapped process its capability token, when one was issued.
    #[must_use]
    pub(crate) fn with_capability_token(mut self, token: Option<&str>) -> Self {
        if let Some(token) = token {
            self.vars
                .insert("FIRMA_CAPABILITY_TOKEN".to_string(), token.to_string());
        }
        self
    }

    /// Name the file a file-sourced capability is read from, so the agent can
    /// pick up rotations without a relaunch.
    #[must_use]
    pub(crate) fn with_capability_source(mut self, source: &CapabilitySource) -> Self {
        if let CapabilitySource::File { path } = source {
            self.vars.insert(
                "FIRMA_CAPABILITY_FILE".to_string(),
                path.display().to_string(),
            );
        }
        self
    }

    /// Return the value set for `key`, if any.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&String> {
        self.vars.get(key)
    }

    /// Return whether `key` is set.
    #[must_use]
    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    /// Set `key`, returning the value it replaced.
    ///
    /// Used by launch preparation that runs after the builder chain, such as the
    /// VS Code shim redirecting `PATH` and the desktop runtime directory.
    pub(crate) fn insert(&mut self, key: String, value: String) -> Option<String> {
        self.vars.insert(key, value)
    }

    /// Iterate the variables in key order.
    pub(crate) fn iter(&self) -> btree_map::Iter<'_, String, String> {
        self.vars.iter()
    }

    /// Return whether no variable is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

impl<'a> IntoIterator for &'a ExecutionEnv {
    type Item = (&'a String, &'a String);
    type IntoIter = btree_map::Iter<'a, String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl From<BTreeMap<String, String>> for ExecutionEnv {
    fn from(vars: BTreeMap<String, String>) -> Self {
        Self { vars }
    }
}
