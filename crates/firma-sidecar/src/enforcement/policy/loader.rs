//! Parses raw policy bundles pushed by the Authority and swaps them
//! into the evaluator atomically.
//!
//! The Authority owns the on-disk bundle source (Component Reference
//! §3.1); the Sidecar never reads bundles from disk (Component
//! Reference §4.6). This loader receives raw bundle payloads from the
//! `WatchPolicyBundle` stream, parses them, and publishes the resulting
//! [`BundleSnapshot`] into the [`CedarPolicyEvaluator`].

use std::sync::Arc;
use std::time::Instant;

use cedar_policy::{Entities, PolicySet, Schema};

use super::evaluator::CedarPolicyEvaluator;
use super::snapshot::BundleSnapshot;

/// Raw bundle payload pushed by the Authority over `WatchPolicyBundle`.
///
/// `policies_cedar` holds the Cedar policy text (human-readable).
/// `schema_json` is optional JSON schema. `entities_json` is the JSON
/// entity store — the empty array `"[]"` when no static entities are
/// shipped.
pub struct RawBundle {
    /// Cedar policy text.
    pub policies_cedar: String,
    /// Optional JSON-serialized Cedar schema.
    pub schema_json: Option<String>,
    /// JSON-serialized entity store.
    pub entities_json: String,
    /// Authority-assigned version.
    pub version: String,
}

/// Errors surfaced while parsing a [`RawBundle`].
///
/// Each variant carries the original parser message; callers log it and
/// retain the previous snapshot — a failed parse must never replace a
/// working bundle.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// Cedar policy set failed to parse.
    #[error("policy parse failed: {0}")]
    Policy(String),
    /// Cedar schema failed to parse.
    #[error("schema parse failed: {0}")]
    Schema(String),
    /// Cedar entity store failed to parse.
    #[error("entities parse failed: {0}")]
    Entities(String),
}

/// Builds [`BundleSnapshot`]s from [`RawBundle`] payloads and atomically
/// installs them into the shared [`CedarPolicyEvaluator`].
///
/// Not a trait — there is exactly one Cedar-based loader. The Authority
/// stream client (task 007) holds one `Arc<BundleLoader>` and calls
/// [`apply`](Self::apply) on every bundle push.
pub struct BundleLoader {
    evaluator: Arc<CedarPolicyEvaluator>,
}

impl BundleLoader {
    /// Build a loader that swaps parsed snapshots into `evaluator`.
    #[must_use]
    pub fn new(evaluator: Arc<CedarPolicyEvaluator>) -> Self {
        Self { evaluator }
    }

    /// Parse `raw` and atomically swap the resulting snapshot into the
    /// evaluator. On any parse failure, the previous snapshot is
    /// retained and the error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::Policy`] / [`BundleError::Schema`] /
    /// [`BundleError::Entities`] when the corresponding parser rejects
    /// the payload.
    pub fn apply(&self, raw: RawBundle) -> Result<(), BundleError> {
        let policies = raw
            .policies_cedar
            .parse::<PolicySet>()
            .map_err(|e| BundleError::Policy(e.to_string()))?;

        let schema = match raw.schema_json.as_deref() {
            Some(src) if !src.trim().is_empty() => {
                Some(Schema::from_json_str(src).map_err(|e| BundleError::Schema(e.to_string()))?)
            }
            _ => None,
        };

        let entities = Entities::from_json_str(&raw.entities_json, schema.as_ref())
            .map_err(|e| BundleError::Entities(e.to_string()))?;

        let snapshot = BundleSnapshot {
            policies,
            schema,
            entities,
            version: raw.version,
            loaded_at: Instant::now(),
        };
        self.evaluator.swap(snapshot);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::evaluator::CedarPolicyEvaluator;
    use super::*;
    use crate::enforcement::constraint_enforcement::PolicyEvaluation;

    fn raw(policies: &str, version: &str) -> RawBundle {
        RawBundle {
            policies_cedar: policies.to_string(),
            schema_json: None,
            entities_json: "[]".to_string(),
            version: version.to_string(),
        }
    }

    fn evaluator() -> Arc<CedarPolicyEvaluator> {
        Arc::new(CedarPolicyEvaluator::empty(Duration::from_secs(30)))
    }

    #[test]
    fn apply_swaps_snapshot() {
        let evaluator = evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));

        loader
            .apply(raw("permit(principal, action, resource);", "v1"))
            .expect("apply ok");

        assert_eq!(evaluator.version().as_deref(), Some("v1"));
    }

    #[test]
    fn apply_rejects_malformed_policy() {
        let evaluator = evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));

        let err = loader.apply(raw("this is not cedar", "v-bad")).unwrap_err();
        assert!(matches!(err, BundleError::Policy(_)), "got: {err}");
    }

    #[test]
    fn apply_rejects_malformed_entities() {
        let evaluator = evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));

        let bad = RawBundle {
            policies_cedar: "permit(principal, action, resource);".to_string(),
            schema_json: None,
            entities_json: "this is not json".to_string(),
            version: "v-bad".to_string(),
        };
        let err = loader.apply(bad).unwrap_err();
        assert!(matches!(err, BundleError::Entities(_)), "got: {err}");
    }

    #[test]
    fn apply_rejects_malformed_schema() {
        let evaluator = evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));

        let bad = RawBundle {
            policies_cedar: "permit(principal, action, resource);".to_string(),
            schema_json: Some("not a schema".to_string()),
            entities_json: "[]".to_string(),
            version: "v-bad".to_string(),
        };
        let err = loader.apply(bad).unwrap_err();
        assert!(matches!(err, BundleError::Schema(_)), "got: {err}");
    }

    #[test]
    fn failed_apply_retains_previous_snapshot() {
        let evaluator = evaluator();
        let loader = BundleLoader::new(Arc::clone(&evaluator));

        loader
            .apply(raw("permit(principal, action, resource);", "v1"))
            .expect("v1 ok");
        let err = loader.apply(raw("broken", "v-bad")).unwrap_err();
        assert!(matches!(err, BundleError::Policy(_)));

        assert_eq!(
            evaluator.version().as_deref(),
            Some("v1"),
            "bad bundle must not replace v1"
        );
    }
}
