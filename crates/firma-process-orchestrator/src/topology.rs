//! Validated component topology for process orchestration.

use std::collections::HashSet;

use crate::{ComponentName, OrchestratorError};

/// Ordered, validated names of every component in a managed stack.
///
/// The topology is the canonical source for startup order and runtime-state
/// filenames throughout the lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackTopology {
    components: Vec<ComponentName>,
}

impl StackTopology {
    /// Validate and construct a topology from names in startup order.
    ///
    /// # Errors
    ///
    /// Returns [`OrchestratorError::InvalidComponentName`] for a name that is
    /// unsafe as a cross-platform runtime-state filename, or
    /// [`OrchestratorError::DuplicateComponentName`] for a duplicate.
    pub fn new<I, S>(names: I) -> Result<Self, OrchestratorError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut seen = HashSet::new();
        let mut components = Vec::new();
        for name in names {
            let component = ComponentName::new(name)?;
            if !seen.insert(component.as_str().to_lowercase()) {
                return Err(OrchestratorError::DuplicateComponentName {
                    name: component.as_str().to_owned(),
                });
            }
            components.push(component);
        }
        Ok(Self { components })
    }

    /// Return components in startup order.
    #[must_use]
    pub(crate) fn components(&self) -> &[ComponentName] {
        &self.components
    }

    pub(crate) fn names(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.components.iter().map(ComponentName::as_str)
    }
}
