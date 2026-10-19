//! Canonical action-class registry view.
//!
//! [`firma_core::ActionClass`] owns the catalog. The Sidecar keeps this facade
//! to preserve its pipeline construction API while deriving validation and
//! enumeration exclusively from [`firma_core::ActionClass::ALL`]. Unknown
//! protected actions fail closed with `DENY: UNCLASSIFIED_INTENT` (FEP
//! \[I-N1\]).

use firma_core::ActionClass;

/// Immutable view of the canonical action-class catalog.
#[derive(Debug, Clone)]
pub struct ActionClassRegistry {
    classes: &'static [ActionClass],
}

impl ActionClassRegistry {
    /// Returns the current canonical registry.
    ///
    /// The versioned constructor name is retained for compatibility. The
    /// returned view is always backed by [`ActionClass::ALL`].
    #[must_use]
    pub const fn v0_1() -> Self {
        Self {
            classes: ActionClass::ALL,
        }
    }

    /// Checks whether an action-class name is canonical.
    #[must_use]
    pub(crate) fn contains(&self, name: &str) -> bool {
        // Parse through the canonical owner so spelling rules cannot drift,
        // then confirm membership in this view's enumeration source.
        name.parse::<ActionClass>()
            .is_ok_and(|class| self.classes.contains(&class))
    }
}
