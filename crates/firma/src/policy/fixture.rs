//! Serde model and context merge for `firma policy test` fixtures.
//!
//! A fixture is a TOML file describing a single Cedar authorization request
//! (principal / action / resource / context) plus the expected decision and
//! the policy-bundle directory to evaluate against. This module owns the
//! deserialization model and the rule for merging a fixture's free-form
//! `[fixture.context]` table onto the canonical context defaults.
//!
//! Parsing is fail-closed: a missing field, an unknown `expected` value, or
//! malformed TOML all surface as [`FixtureError`] and the caller exits
//! non-zero. The context-merge step is intentionally permissive — unknown
//! keys are passed through untouched so that Cedar's schema-strict request
//! build (not this module) is the single place that rejects out-of-schema
//! attributes, keeping fixture evaluation identical to the hot path.
//!
//! The defaults built by [`default_context`] mirror the Sidecar hot path
//! (`ConstraintEnforcer::build_context`) exactly: all fifteen required
//! `EnforcementContext` attributes are supplied, so a `firma policy test`
//! verdict equals the enforcement verdict for the equivalent plain request.
//! The five payment fields plus `raw_transport` default to the same fixed
//! placeholders the hot path uses today and are overridable via
//! `[fixture.context]`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

/// The decision a fixture asserts the bundle should produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// The request must be authorized.
    Allow,
    /// The request must be denied.
    Deny,
}

impl std::fmt::Display for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => f.write_str("ALLOW"),
            Self::Deny => f.write_str("DENY"),
        }
    }
}

impl<'de> Deserialize<'de> for Expected {
    /// Deserialize `expected` case-insensitively.
    ///
    /// `serde(alias)` cannot express case-insensitivity, so the raw string is
    /// read and matched against an ASCII-folded form. Any other value is a
    /// hard error (fail-closed): a fixture that misspells the expectation must
    /// not silently default.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.to_ascii_uppercase().as_str() {
            "ALLOW" => Ok(Self::Allow),
            "DENY" => Ok(Self::Deny),
            other => Err(serde::de::Error::custom(format!(
                "expected must be \"ALLOW\" or \"DENY\" (case-insensitive), got {other:?}"
            ))),
        }
    }
}

/// Principal section of a fixture.
#[derive(Debug, Clone, Deserialize)]
pub struct FixturePrincipal {
    /// Agent id; parsed into [`firma_core::AgentId`] downstream.
    pub agent_id: String,
}

/// Action section of a fixture.
#[derive(Debug, Clone, Deserialize)]
pub struct FixtureAction {
    /// Action class, e.g. `model.inference.chat`.
    pub class: String,
}

/// Resource section of a fixture.
#[derive(Debug, Clone, Deserialize)]
pub struct FixtureResource {
    /// Resource host; becomes the `Firma::Resource` entity id.
    pub host: String,
}

/// The `[fixture]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct FixtureSpec {
    /// Asserted decision (case-insensitive `ALLOW`/`DENY`).
    pub expected: Expected,
    pub principal: FixturePrincipal,
    pub action: FixtureAction,
    pub resource: FixtureResource,
    /// Optional context overrides; keys replace context defaults by name.
    #[serde(default)]
    pub context: BTreeMap<String, toml::Value>,
}

/// The `[bundle]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct BundleSpec {
    /// Path to the `*.cedar` bundle directory, resolved relative to the
    /// fixture file's parent directory by the runner.
    pub path: String,
}

/// A fully parsed fixture file.
#[derive(Debug, Clone, Deserialize)]
pub struct Fixture {
    pub fixture: FixtureSpec,
    pub bundle: BundleSpec,
}

/// Errors produced while parsing a fixture file.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The fixture file could not be read.
    #[error("cannot read fixture '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The fixture file is not valid fixture TOML.
    #[error("invalid fixture '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

impl Fixture {
    /// Parse the fixture TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`FixtureError::Read`] if the file cannot be read or
    /// [`FixtureError::Parse`] if it is not a well-formed fixture (missing
    /// required fields, bad `expected`, malformed TOML).
    pub fn from_path(path: &Path) -> Result<Self, FixtureError> {
        let source = std::fs::read_to_string(path).map_err(|source| FixtureError::Read {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&source).map_err(|source| FixtureError::Parse {
            path: path.display().to_string(),
            source,
        })
    }
}

/// Build the canonical default Cedar context object.
///
/// The canonical Firma schema declares **fifteen required**
/// `EnforcementContext` attributes. This default mirrors the Sidecar hot path
/// (`ConstraintEnforcer::build_context` in
/// `firma-sidecar/src/enforcement/constraint_enforcement.rs`, ~L375-389) so a
/// `policy test` verdict equals the enforcement verdict for the equivalent
/// plain (no-payment) request. Every attribute is supplied; all are
/// overridable via `[fixture.context]`.
///
/// Default origins:
///
/// - `session_id`, `timestamp_ms`, `params`, `risk_score`,
///   `session_duration_s`, `action_count` — the six user-facing defaults
///   defined by the `firma policy test` contract (`timestamp_ms` is current
///   Unix time in ms so a fixture need not pin it).
/// - `raw_transport` — `"https"`, mirroring the sidecar value for an HTTPS
///   request (`normalizer.rs` sets `"https"`/`"http"` from `request.is_https`;
///   the canonical envelope baseline throughout `firma-core` is `"https"`).
/// - `transfer_amount`, `daily_cumulative_amount`, `transfers_last_10m`,
///   `same_payee_count_30m`, `session_transfer_count` — `0`, the exact fixed
///   placeholders the sidecar `build_context` supplies for a non-payment
///   action today.
#[must_use]
pub fn default_context() -> serde_json::Map<String, serde_json::Value> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_i64, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));

    let mut ctx = serde_json::Map::new();
    // Six user-facing defaults from the `firma policy test` contract.
    ctx.insert("session_id".into(), serde_json::Value::from("fixture"));
    ctx.insert("timestamp_ms".into(), serde_json::Value::from(now_ms));
    ctx.insert("params".into(), serde_json::Value::from("{}"));
    ctx.insert("risk_score".into(), serde_json::Value::from(0_i64));
    ctx.insert("session_duration_s".into(), serde_json::Value::from(0_i64));
    ctx.insert("action_count".into(), serde_json::Value::from(1_i64));
    // Six fields mirrored from sidecar `build_context` so a fixture verdict
    // matches the hot path for the equivalent plain request.
    ctx.insert("raw_transport".into(), serde_json::Value::from("https"));
    ctx.insert("transfer_amount".into(), serde_json::Value::from(0_i64));
    ctx.insert(
        "daily_cumulative_amount".into(),
        serde_json::Value::from(0_i64),
    );
    ctx.insert("transfers_last_10m".into(), serde_json::Value::from(0_i64));
    ctx.insert(
        "same_payee_count_30m".into(),
        serde_json::Value::from(0_i64),
    );
    ctx.insert(
        "session_transfer_count".into(),
        serde_json::Value::from(0_i64),
    );
    // Three prior-action context fields (AARM R2 G3): mirror the sidecar
    // hot path which surfaces the bounded session history. Defaults reflect
    // a fresh session: no prior denials, no prior action classes, no last
    // resource.
    ctx.insert("deny_count".into(), serde_json::Value::from(0_i64));
    ctx.insert(
        "prior_action_classes".into(),
        serde_json::Value::Array(Vec::new()),
    );
    ctx.insert("last_resource".into(), serde_json::Value::from(""));
    ctx
}

/// Convert a TOML value into the JSON value Cedar's context builder expects.
///
/// Integers map to JSON numbers, floats to JSON numbers, booleans/strings
/// pass through, and arrays/tables/datetimes recurse so an override can carry
/// nested structure. Datetimes are stringified (Cedar has no native datetime
/// in this schema) so they remain inspectable rather than being dropped.
fn toml_to_json(value: &toml::Value) -> serde_json::Value {
    match value {
        toml::Value::String(s) => serde_json::Value::from(s.clone()),
        toml::Value::Integer(i) => serde_json::Value::from(*i),
        toml::Value::Float(f) => serde_json::Value::from(*f),
        toml::Value::Boolean(b) => serde_json::Value::from(*b),
        toml::Value::Datetime(dt) => serde_json::Value::from(dt.to_string()),
        toml::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => serde_json::Value::Object(
            table
                .iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect(),
        ),
    }
}

/// Merge a fixture's `[fixture.context]` overrides onto the defaults.
///
/// Each override key replaces the same key in [`default_context`]; unknown
/// keys are inserted verbatim (not filtered). Schema rejection of unknown or
/// wrongly-typed keys is deferred to Cedar's request build so fixture
/// evaluation matches enforcement exactly.
#[must_use]
pub fn merged_context(overrides: &BTreeMap<String, toml::Value>) -> serde_json::Value {
    let mut ctx = default_context();
    for (key, value) in overrides {
        ctx.insert(key.clone(), toml_to_json(value));
    }
    serde_json::Value::Object(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[fixture]
expected = "ALLOW"

[fixture.principal]
agent_id = "agt_01j0000000e008000000000001"

[fixture.action]
class = "model.inference.chat"

[fixture.resource]
host = "api.openai.com"

[fixture.context]
action_count = 1000

[bundle]
path = ".firma/policies/"
"#;

    #[test]
    fn parses_full_fixture() {
        let fx: Fixture = toml::from_str(SAMPLE).expect("parse fixture");
        assert_eq!(fx.fixture.expected, Expected::Allow);
        assert_eq!(
            fx.fixture.principal.agent_id,
            "agt_01j0000000e008000000000001"
        );
        assert_eq!(fx.fixture.action.class, "model.inference.chat");
        assert_eq!(fx.fixture.resource.host, "api.openai.com");
        assert_eq!(fx.bundle.path, ".firma/policies/");
        assert_eq!(
            fx.fixture.context.get("action_count"),
            Some(&toml::Value::Integer(1000))
        );
    }

    #[test]
    fn context_is_optional() {
        let src = r#"
[fixture]
expected = "DENY"
[fixture.principal]
agent_id = "a"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "api.github.com"
[bundle]
path = "p/"
"#;
        let fx: Fixture = toml::from_str(src).expect("parse without context");
        assert!(fx.fixture.context.is_empty());
    }

    #[test]
    fn expected_is_case_insensitive() {
        for (raw, want) in [
            ("ALLOW", Expected::Allow),
            ("allow", Expected::Allow),
            ("Allow", Expected::Allow),
            ("DENY", Expected::Deny),
            ("deny", Expected::Deny),
            ("Deny", Expected::Deny),
        ] {
            let src = format!(
                r#"
[fixture]
expected = "{raw}"
[fixture.principal]
agent_id = "a"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "h"
[bundle]
path = "p/"
"#
            );
            let fx: Fixture = toml::from_str(&src).expect("parse expected");
            assert_eq!(fx.fixture.expected, want, "raw={raw}");
        }
    }

    #[test]
    fn expected_rejects_unknown_value() {
        let src = r#"
[fixture]
expected = "MAYBE"
[fixture.principal]
agent_id = "a"
[fixture.action]
class = "code.read"
[fixture.resource]
host = "h"
[bundle]
path = "p/"
"#;
        let err = toml::from_str::<Fixture>(src).unwrap_err();
        assert!(
            err.to_string().contains("ALLOW") || err.to_string().contains("DENY"),
            "error should explain valid values; got {err}"
        );
    }

    #[test]
    fn merge_keeps_defaults_when_no_override() {
        let ctx = merged_context(&BTreeMap::new());
        let obj = ctx.as_object().unwrap();
        assert_eq!(
            obj.get("session_id"),
            Some(&serde_json::Value::from("fixture"))
        );
        assert_eq!(obj.get("risk_score"), Some(&serde_json::Value::from(0_i64)));
        assert_eq!(
            obj.get("action_count"),
            Some(&serde_json::Value::from(1_i64))
        );
        // All fifteen schema-required attributes present, mirroring the
        // sidecar `build_context` defaults.
        assert_eq!(
            obj.get("raw_transport"),
            Some(&serde_json::Value::from("https"))
        );
        assert_eq!(
            obj.get("transfer_amount"),
            Some(&serde_json::Value::from(0_i64))
        );
        assert_eq!(
            obj.get("daily_cumulative_amount"),
            Some(&serde_json::Value::from(0_i64))
        );
        assert_eq!(
            obj.get("transfers_last_10m"),
            Some(&serde_json::Value::from(0_i64))
        );
        assert_eq!(
            obj.get("same_payee_count_30m"),
            Some(&serde_json::Value::from(0_i64))
        );
        assert_eq!(
            obj.get("session_transfer_count"),
            Some(&serde_json::Value::from(0_i64))
        );
        assert_eq!(obj.len(), 15);
    }

    #[test]
    fn default_context_has_fifteen_required_attributes() {
        let ctx = default_context();
        for key in [
            "session_id",
            "timestamp_ms",
            "params",
            "risk_score",
            "session_duration_s",
            "action_count",
            "raw_transport",
            "deny_count",
            "prior_action_classes",
            "last_resource",
            "transfer_amount",
            "daily_cumulative_amount",
            "transfers_last_10m",
            "same_payee_count_30m",
            "session_transfer_count",
        ] {
            assert!(ctx.contains_key(key), "missing required attribute {key}");
        }
        assert_eq!(ctx.len(), 15);
    }

    #[test]
    fn merge_override_replaces_default() {
        let mut over = BTreeMap::new();
        over.insert("risk_score".to_string(), toml::Value::Integer(1000));
        let ctx = merged_context(&over);
        let obj = ctx.as_object().unwrap();
        assert_eq!(
            obj.get("risk_score"),
            Some(&serde_json::Value::from(1000_i64))
        );
    }

    #[test]
    fn merge_override_replaces_payment_default() {
        let mut over = BTreeMap::new();
        over.insert("transfer_amount".to_string(), toml::Value::Integer(500));
        let ctx = merged_context(&over);
        let obj = ctx.as_object().unwrap();
        // A mirrored payment default is overridable; count stays at 15.
        assert_eq!(
            obj.get("transfer_amount"),
            Some(&serde_json::Value::from(500_i64))
        );
        assert_eq!(obj.len(), 15);
    }

    #[test]
    fn merge_passes_through_unknown_key() {
        let mut over = BTreeMap::new();
        over.insert("not_in_schema".to_string(), toml::Value::Integer(7));
        let ctx = merged_context(&over);
        let obj = ctx.as_object().unwrap();
        // A key outside the schema is preserved verbatim, not filtered —
        // Cedar's schema-strict request build is the single rejector.
        assert_eq!(
            obj.get("not_in_schema"),
            Some(&serde_json::Value::from(7_i64))
        );
        assert_eq!(obj.len(), 16);
    }
}
