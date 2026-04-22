//! Canonical Action Class Registry v0.1.
//!
//! Contains the 15 canonical action classes defined by FEP v0.1 §2.3.5.
//! Every `intent.action_class` field in an `ExecutionEnvelope` MUST be one
//! of these identifiers. Unknown protected actions that cannot be
//! deterministically mapped to a registry entry fail closed with
//! `DENY: UNCLASSIFIED_INTENT` (FEP \[I-N1\]).
//!
//! Identifiers follow the naming rules in FEP §2.3.2: lowercase ASCII,
//! dot-separated, describing semantic meaning only. Transport, provider,
//! and connector names MUST NOT appear in identifiers. See
//! `docs/markdown/firma_action_class_registry.md` for the implementation
//! notes and default mapping strategy.
//!
//! The same canonical class is produced regardless of whether the underlying
//! action arrives as a native tool call, a CLI invocation, an HTTP request,
//! or an MCP call. Policies and HITL conditions bind to the canonical action
//! class, not to transport-specific names.

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
#[expect(
    dead_code,
    reason = "fields read by policy evaluation and audit once wired"
)]
#[derive(Debug, Clone)]
pub struct ActionClassDefinition {
    pub name: &'static str,
    pub domain: &'static str,
    pub risk_level: RiskLevel,
}

/// The v0.1 Canonical Action Class Registry.
///
/// Contains all 15 action classes defined by FEP v0.1 §2.3.5. Immutable
/// after construction — runtime extension is not permitted by the spec.
#[derive(Debug, Clone)]
pub struct ActionClassRegistry {
    classes: HashMap<&'static str, ActionClassDefinition>,
}

impl ActionClassRegistry {
    /// Build the v0.1 registry with all 15 canonical action classes from
    /// FEP §2.3.5.
    #[must_use]
    pub fn v0_1() -> Self {
        use RiskLevel::{Critical, High, Low, Medium};

        let entries: Vec<ActionClassDefinition> = vec![
            ActionClassDefinition {
                name: "account.permission.change",
                domain: "account",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "browser.purchase",
                domain: "browser",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "communication.external.send",
                domain: "communication",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "communication.internal.send",
                domain: "communication",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "credential.read",
                domain: "credential",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "credential.write",
                domain: "credential",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "filesystem.delete",
                domain: "filesystem",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "filesystem.read",
                domain: "filesystem",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "filesystem.write",
                domain: "filesystem",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "memory.cross_namespace.read",
                domain: "memory",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "memory.cross_namespace.write",
                domain: "memory",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "payment.purchase",
                domain: "payment",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "payment.transfer",
                domain: "payment",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "system.execute",
                domain: "system",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "system.install",
                domain: "system",
                risk_level: High,
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
    #[expect(dead_code, reason = "public API for policy evaluation callers")]
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ActionClassDefinition> {
        self.classes.get(name)
    }

    /// Return the number of registered action classes.
    #[expect(dead_code, reason = "public API for diagnostics/health callers")]
    #[must_use]
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Check if the registry is empty.
    #[expect(dead_code, reason = "public API for diagnostics/health callers")]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The exact 15 identifiers defined by FEP v0.1 §2.3.5. Drift from this
    /// list is a spec conformance bug.
    const FEP_V0_1_CLASSES: &[&str] = &[
        "account.permission.change",
        "browser.purchase",
        "communication.external.send",
        "communication.internal.send",
        "credential.read",
        "credential.write",
        "filesystem.delete",
        "filesystem.read",
        "filesystem.write",
        "memory.cross_namespace.read",
        "memory.cross_namespace.write",
        "payment.purchase",
        "payment.transfer",
        "system.execute",
        "system.install",
    ];

    #[test]
    fn test_v0_1_registry_has_15_classes() {
        let registry = ActionClassRegistry::v0_1();
        assert_eq!(registry.len(), 15);
    }

    #[test]
    fn test_v0_1_registry_matches_fep_spec() {
        let registry = ActionClassRegistry::v0_1();
        for class in FEP_V0_1_CLASSES {
            assert!(
                registry.contains(class),
                "FEP v0.1 class missing from registry: {class}"
            );
        }
    }

    #[test]
    fn test_v0_1_registry_rejects_transport_names() {
        let registry = ActionClassRegistry::v0_1();
        for forbidden in [
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
            "network.connect",
            "messaging.send",
            "llm.inference",
            "gmail.send",
            "tool.email.send",
        ] {
            assert!(
                !registry.contains(forbidden),
                "non-conformant identifier present in registry: {forbidden}"
            );
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

    #[test]
    fn test_payment_transfer_is_critical() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("payment.transfer");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Critical));
    }

    #[test]
    fn test_filesystem_read_is_low_risk() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("filesystem.read");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Low));
    }
}
