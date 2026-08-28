//! Schema for `[sidecar.capability_seed]`.
//!
//! Representation only. Lists pre-issued capability seed files the sidecar
//! loads at startup. `firma-sidecar` validates that every path is non-empty and
//! requires its configured parent and resolved target to stay beneath the
//! selected runtime state's `capabilities/` directory.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// `[sidecar.capability_seed]` TOML section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySeedConfig {
    /// Existing seed TOML files produced by `firma authority issue`. Every
    /// resolved path must be beneath `<state-dir>/capabilities/`. An empty list
    /// means no static seeding.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// When `true` (default), the sidecar watches the seed file(s) and
    /// hot-swaps its `CapabilityMap` when they change. Set `false` to pin the
    /// map loaded at startup.
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
}

/// Default for [`CapabilitySeedConfig::hot_reload`].
const fn default_hot_reload() -> bool {
    true
}

impl Default for CapabilitySeedConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            hot_reload: default_hot_reload(),
        }
    }
}
