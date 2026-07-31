//! Embedded policy profile registry.
//!
//! Authority autostart materialises one of these into its per-run policy
//! directory on first boot. Today only `developer` is registered; future
//! profiles (`read_only`, `balanced`, `strict`, `production_safe`) plug
//! into the same `cedar_for` dispatch.

mod developer;

pub use developer::DEVELOPER_CEDAR;

/// Profile name used when a caller does not request one explicitly.
///
/// Single source of truth shared by the authority registry and the
/// `firma run` / `firma-run` config defaults.
pub const DEFAULT_PROFILE: &str = "developer";

/// Returned when a caller asks for a profile name we do not ship.
#[derive(Debug, thiserror::Error)]
#[error("unknown authority profile `{name}`")]
pub struct UnknownProfileError {
    pub name: String,
}

/// Resolve a profile name to its embedded cedar source.
///
/// # Errors
///
/// Returns [`UnknownProfileError`] when the name is not registered.
pub fn cedar_for(name: &str) -> Result<&'static str, UnknownProfileError> {
    match name {
        DEFAULT_PROFILE => Ok(DEVELOPER_CEDAR),
        other => Err(UnknownProfileError {
            name: other.to_string(),
        }),
    }
}
