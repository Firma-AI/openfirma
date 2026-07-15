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
    /// Build the v0.1 registry: 15 canonical FEP §2.3.5 classes plus 29
    /// in-place additions covering the GitHub (12), Stripe (12), and
    /// Gmail (5) REST surfaces, and the `secret.mediate` governance
    /// action (45 total).
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "the canonical v0.1 action-class registry is maintained as one declarative literal"
    )]
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
            // ----- GitHub coverage additions -----
            ActionClassDefinition {
                name: "code.read",
                domain: "code",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "code.review.read",
                domain: "code",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "code.review.submit",
                domain: "code",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "code.write",
                domain: "code",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "code.destructive",
                domain: "code",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "code.merge",
                domain: "code",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "issue.read",
                domain: "issue",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "issue.write",
                domain: "issue",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "notification.manage",
                domain: "notification",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "security.alert.read",
                domain: "security",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "repo.lifecycle",
                domain: "repo",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "repo.admin",
                domain: "repo",
                risk_level: Critical,
            },
            // ----- Stripe coverage additions -----
            ActionClassDefinition {
                name: "payment.read",
                domain: "payment",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "payment.cancel",
                domain: "payment",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "payment.refund",
                domain: "payment",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "payment.payout",
                domain: "payment",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "payment.dispute",
                domain: "payment",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "payment.subscription",
                domain: "payment",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "payment.method.setup",
                domain: "payment",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "payment.method.manage",
                domain: "payment",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "payment.catalog.write",
                domain: "payment",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "payment.tax",
                domain: "payment",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "customer.read",
                domain: "customer",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "customer.write",
                domain: "customer",
                risk_level: Medium,
            },
            // ----- Gmail coverage additions -----
            ActionClassDefinition {
                name: "communication.external.read",
                domain: "communication",
                risk_level: Low,
            },
            ActionClassDefinition {
                name: "communication.external.draft",
                domain: "communication",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "communication.external.manage",
                domain: "communication",
                risk_level: Medium,
            },
            ActionClassDefinition {
                name: "communication.external.delete",
                domain: "communication",
                risk_level: High,
            },
            ActionClassDefinition {
                name: "communication.external.filter",
                domain: "communication",
                risk_level: Critical,
            },
            ActionClassDefinition {
                name: "secret.mediate",
                domain: "secret",
                risk_level: Critical,
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

    /// Registry identifiers.
    ///
    /// The first 15 are FEP v0.1 §2.3.5 canonical classes. The remaining 29
    /// cover the GitHub (12), Stripe (12), and Gmail (5) REST surfaces and
    /// are appended in-place without a registry version bump.
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
        // GitHub coverage additions.
        "code.read",
        "code.review.read",
        "code.review.submit",
        "code.write",
        "code.destructive",
        "code.merge",
        "issue.read",
        "issue.write",
        "notification.manage",
        "security.alert.read",
        "repo.lifecycle",
        "repo.admin",
        // Stripe coverage additions.
        "payment.read",
        "payment.cancel",
        "payment.refund",
        "payment.payout",
        "payment.dispute",
        "payment.subscription",
        "payment.method.setup",
        "payment.method.manage",
        "payment.catalog.write",
        "payment.tax",
        "customer.read",
        "customer.write",
        // Gmail coverage additions.
        "communication.external.read",
        "communication.external.draft",
        "communication.external.manage",
        "communication.external.delete",
        "communication.external.filter",
    ];

    #[test]
    fn test_v0_1_registry_has_45_classes() {
        let registry = ActionClassRegistry::v0_1();
        assert_eq!(registry.len(), 45);
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

    /// The `firma_core::ActionClass` enum is the typed mirror of this registry.
    /// Assert both directions so the two cannot drift: every enum variant is a
    /// registry entry, and every registry entry parses back into a variant.
    #[test]
    fn action_class_enum_matches_registry() {
        use firma_core::ActionClass;

        let registry = ActionClassRegistry::v0_1();
        for class in ActionClass::ALL {
            assert!(
                registry.contains(class.as_str()),
                "ActionClass::{class:?} missing from registry"
            );
        }
        assert_eq!(
            ActionClass::ALL.len(),
            registry.len(),
            "ActionClass and registry differ in size"
        );
        for name in FEP_V0_1_CLASSES {
            assert!(
                name.parse::<ActionClass>().is_ok(),
                "registry class not in ActionClass enum: {name}"
            );
        }
    }

    #[test]
    fn test_payment_payout_is_critical() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("payment.payout");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Critical));
    }

    #[test]
    fn test_payment_refund_is_high() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("payment.refund");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::High));
    }

    #[test]
    fn test_payment_read_is_low() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("payment.read");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Low));
    }

    #[test]
    fn test_communication_external_filter_is_critical() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("communication.external.filter");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Critical));
    }

    #[test]
    fn test_communication_external_delete_is_high() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("communication.external.delete");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::High));
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

    #[test]
    fn test_code_merge_is_critical() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("code.merge");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Critical));
    }

    #[test]
    fn test_repo_admin_is_critical() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("repo.admin");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Critical));
    }

    #[test]
    fn test_code_read_is_low_risk() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("code.read");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::Low));
    }

    #[test]
    fn test_code_write_is_high_risk() {
        let registry = ActionClassRegistry::v0_1();
        let def = registry.get("code.write");
        assert_eq!(def.map(|d| d.risk_level), Some(RiskLevel::High));
    }

    #[test]
    fn test_registry_is_aligned_with_core_schema() {
        let registry = ActionClassRegistry::v0_1();
        let (schema, _warnings) =
            cedar_policy::Schema::from_cedarschema_str(firma_core::cedar::FIRMA_SCHEMA).unwrap();
        for action in schema.actions() {
            assert!(
                registry.get(action.id().as_ref()).is_some(),
                "Missing {action}"
            );
        }
    }

    #[test]
    fn test_core_schema_is_aligned_with_registry() {
        let registry = ActionClassRegistry::v0_1();
        let (schema, _warnings) =
            cedar_policy::Schema::from_cedarschema_str(firma_core::cedar::FIRMA_SCHEMA).unwrap();
        let action_entities = schema.action_entities().unwrap();
        for action in registry.classes.values() {
            let entity_id = cedar_policy::EntityUid::try_from(firma_core::FirmaEntityUid::Action(
                action.name.to_owned(),
            ))
            .unwrap();
            assert!(
                action_entities.get(&entity_id).is_some(),
                "Missing {entity_id}"
            );
        }
    }
}
