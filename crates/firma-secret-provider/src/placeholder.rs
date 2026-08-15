//! Placeholder token minting
//!
//! Shared by firma-run's CLI intercept (which also owns the canonical
//! `Placeholder` dictionary-key type and the persistent `SecretStore`) and
//! firma-sidecar's HTTP MITM intercept (which mints locally so its
//! single-pass extraction can substitute the placeholder synchronously, then
//! pushes the pre-minted placeholder and value to firma-run's broker for
//! storage).

use type_safe_id::{StaticType, TypeSafeId};

// fsp = firma secret placeholder
pub const PLACEHOLDER_PREFIX: &str = "fsp_";

/// Byte length of [`SecretPlaceholder`]'s base32 UUID suffix (per the
/// type-safe-id spec, 26 Crockford-base32 characters).
///
/// A valid token is exactly `PLACEHOLDER_PREFIX.len() +
/// PLACEHOLDER_SUFFIX_LEN` bytes.
pub const PLACEHOLDER_SUFFIX_LEN: usize = 26;

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
    // must be `PLACEHOLDER_PREFIX` without the final underscore
    const TYPE: &'static str = "fsp";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_prefix_is_aligned() {
        assert_eq!(
            <Inner as StaticType>::TYPE,
            &PLACEHOLDER_PREFIX[0..PLACEHOLDER_PREFIX.len() - 1]
        );
    }

    #[test]
    fn placeholder_length_is_correct() {
        let placeholder = SecretPlaceholder::new();
        assert_eq!(
            placeholder.to_string().len(),
            PLACEHOLDER_PREFIX.len() + PLACEHOLDER_SUFFIX_LEN
        );
    }
}
