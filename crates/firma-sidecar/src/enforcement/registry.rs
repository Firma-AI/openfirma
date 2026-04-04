use std::collections::HashMap;

/// Risk level associated with an action class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Definition of a single action class in the registry.
#[derive(Debug, Clone)]
pub struct ActionClassDefinition {
    pub name: &'static str,
    pub domain: &'static str,
    pub risk_level: RiskLevel,
}

/// The v0.1 Canonical Action Class Registry.
///
/// Contains all 15 action classes that the enforcement pipeline understands.
/// Immutable after construction — defined at compile time for V1.
#[derive(Debug, Clone)]
pub struct ActionClassRegistry {
    classes: HashMap<&'static str, ActionClassDefinition>,
}

impl ActionClassRegistry {
    /// Build the v0.1 registry with all 15 canonical action classes.
    #[must_use]
    pub fn v0_1() -> Self {
        use RiskLevel::{Critical, High, Low, Medium};

        let entries: Vec<ActionClassDefinition> = vec![
            ActionClassDefinition {
                name: "http.get",
                domain: "network",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "http.post",
                domain: "network",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "http.put",
                domain: "network",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "http.delete",
                domain: "network",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "http.patch",
                domain: "network",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "db.query",
                domain: "database",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "db.mutate",
                domain: "database",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "file.read",
                domain: "file_io",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "file.write",
                domain: "file_io",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "file.delete",
                domain: "file_io",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "code.execute",
                domain: "execution",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "system.execute",
                domain: "execution",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "network.connect",
                domain: "network",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "messaging.send",
                domain: "communication",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "llm.inference",
                domain: "ai",
                risk_level: Low,
            },
        ];

        let mut classes = HashMap::with_capacity(entries.len());
        for entry in entries {
            classes.insert(entry.name, entry);
        }

        Self { classes }
    }

    /// Check if an action class name is in the registry.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.classes.contains_key(name)
    }

    /// Get the definition for an action class.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ActionClassDefinition> {
        self.classes.get(name)
    }

    /// Return the number of registered action classes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Check if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v0_1_registry_has_15_classes() {
        let registry = ActionClassRegistry::v0_1();
        assert_eq!(registry.len(), 15);
    }

    #[test]
    fn test_v0_1_registry_contains_all_classes() {
        let registry = ActionClassRegistry::v0_1();
        let expected = [
            "http.get",
            "http.post",
            "http.put",
            "http.delete",
            "http.patch",
            "db.query",
            "db.mutate",
            "file.read",
            "file.write",
            "file.delete",
            "code.execute",
            "system.execute",
            "network.connect",
            "messaging.send",
            "llm.inference",
        ];
        for class in expected {
            assert!(registry.contains(class), "missing action class: {class}");
        }
    }

    #[test]
    fn test_unknown_class_not_in_registry() {
        let registry = ActionClassRegistry::v0_1();
        assert!(!registry.contains("unknown.action"));
    }

    #[test]
    fn test_system_execute_is_critical() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("system.execute");
        assert!(def.is_some());
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Critical));
    }
}
