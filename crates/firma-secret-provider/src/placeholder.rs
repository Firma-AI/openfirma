//! Placeholder token minting
//!
//! Shared by firma-run's CLI intercept (which also owns the canonical
//! `Placeholder` dictionary-key type and the persistent `SecretStore`) and
//! firma-sidecar's HTTP MITM intercept (which mints locally so its
//! single-pass extraction can substitute the placeholder synchronously, then
//! pushes the pre-minted placeholder and value to firma-run's broker for
//! storage).

use type_safe_id::{StaticType, TypeSafeId};

/// Opaque token substituted for a secret value in extraction output.
///
/// Minted per extracted secret and returned to the caller-supplied `mint`
/// callback in [`CompiledMatcher::rewrite`](crate::CompiledMatcher::rewrite);
/// the caller is responsible for persisting the `SecretPlaceholder -> value`
/// mapping.
pub type SecretPlaceholder = TypeSafeId<Inner>;

/// Marker type binding [`SecretPlaceholder`] to its `fsp` `TypeSafeId` prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Inner;

impl StaticType for Inner {
    // fsp = firma secret placeholder
    const TYPE: &'static str = "fsp";
}
