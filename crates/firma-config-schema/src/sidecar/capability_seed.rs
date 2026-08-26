//! Schema for `[sidecar.capability_seed]`.
//!
//! Representation only. Lists pre-issued capability seed files the sidecar
//! loads at startup. `firma-sidecar` validates that no path is empty.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// `[capability_seed]` TOML section.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySeedConfig {
    /// Paths to seed TOML files produced by `firma-authority issue`. Empty
    /// list means no static seeding.
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
