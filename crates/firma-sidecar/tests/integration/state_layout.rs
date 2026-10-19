//! Shared state-directory helper for configuration-loading tests.

use std::path::Path;

use firma_runtime_state::RuntimeLayout;

/// A state directory beside `config_path` that holds no generated material.
///
/// [`firma_sidecar::config::SidecarConfig::load_from_path`] resolves unset
/// artifact paths against a state directory and adopts the Authority trust
/// anchors it finds there. Cases about the config file itself must therefore
/// point at an empty one rather than the developer's real state directory.
pub fn empty_state_beside(config_path: &Path) -> RuntimeLayout {
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    RuntimeLayout::from_root(parent.join("state"))
}
