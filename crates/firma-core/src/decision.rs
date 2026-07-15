use http::HeaderName;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Typed reason code explaining why an already-authorized request was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum AbortReason {
    /// Outbound connector exceeded its configured timeout.
    #[error("connector timeout")]
    ConnectorTimeout,
    /// Outbound connector failed before producing a target response.
    #[error("connector failure")]
    ConnectorFailure,
    /// Outbound connector rejected the authorized envelope shape.
    #[error("connector invalid request")]
    ConnectorInvalidRequest,
    /// Sidecar failed to inject credentials after enforcement allowed the call.
    #[error("credential injection failed")]
    CredentialInjectionFailed,
}

impl AbortReason {
    /// Canonical reason code string used in audit events and agent responses.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConnectorTimeout => "CONNECTOR_TIMEOUT",
            Self::ConnectorFailure => "CONNECTOR_FAILURE",
            Self::ConnectorInvalidRequest => "CONNECTOR_INVALID_REQUEST",
            Self::CredentialInjectionFailed => "CREDENTIAL_INJECTION_FAILED",
        }
    }
}

/// Outcome of policy evaluation.
///
/// Every enforcement decision in Firma maps to one of these three variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Request passes all checks. Proceed with execution.
    Allow,
    /// Request denied. Return error to agent with reason code.
    Deny { reason: DenyReason },
    /// Critical failure. Kill the session/execution immediately.
    Abort { reason: String },
}

/// Typed reason code explaining why a request was denied.
///
/// Backlog variant (add back when the corresponding mechanism exists):
/// - `RiskThreshold` — when anomaly detection is designed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum DenyReason {
    /// Signature check failed or unrecognized token format.
    #[error("token invalid")]
    TokenInvalid,
    /// Token TTL has elapsed.
    #[error("token expired")]
    TokenExpired,
    /// Token has been explicitly revoked.
    #[error("token revoked")]
    TokenRevoked,
    /// Cedar policy evaluation returned deny.
    #[error("policy denied")]
    PolicyDenied,
    /// Action or resource outside the token's granted scope.
    #[error("scope violation")]
    ScopeViolation,
    /// Specific tool not in the token's allowed set.
    #[error("tool not in scope")]
    ToolNotInScope,
    /// Execution envelope failed validation.
    #[error("malformed request")]
    MalformedRequest,
    /// Cannot reach Authority for token validation.
    #[error("authority unavailable")]
    AuthorityUnavailable,
    /// Policy bundle TTL exceeded, no fresh bundle available.
    #[error("policy bundle stale")]
    PolicyBundleStale,
    /// Initial policy bundle has not been applied yet.
    #[error("policy bundle not ready")]
    PolicyBundleNotReady,
    /// Initial revocation state has not been applied yet.
    #[error("revocation cache not ready")]
    RevocationCacheNotReady,
    /// Fail-closed safety boundary triggered due to missing/invalid enforcement prerequisites.
    #[error("fail closed")]
    FailClosed,
    /// Enforcement evaluation exceeded configured timeout budget.
    #[error("enforcement timeout")]
    EnforcementTimeout,
    /// Sidecar failed to inject credentials for Stage 3.
    ///
    /// No current producer: credential-injection failure after ALLOW is
    /// raised as [`AbortReason::CredentialInjectionFailed`] (FIR-46), not a
    /// DENY. Retained for serialized backward compatibility of this enum.
    #[error("credential injection failed")]
    CredentialInjectionFailed,
    /// Outbound connector timed out.
    #[error("connector timeout")]
    ConnectorTimeout,
    /// Outbound connector failed at the transport layer (DNS, TCP,
    /// TLS, connection reset).
    #[error("connector network error")]
    ConnectorNetworkError,
    /// Outbound connector could not translate the envelope into a
    /// well-formed target request.
    ///
    /// No current producer: a connector that fails to build a request after
    /// ALLOW is raised as [`AbortReason::ConnectorInvalidRequest`] (FIR-46),
    /// not a DENY. Retained for serialized backward compatibility of this enum.
    #[error("connector invalid request")]
    ConnectorInvalidRequest,
    /// Protected action could not be mapped to any canonical action class.
    #[error("unclassified intent")]
    UnclassifiedIntent,
    /// Token's `agent_id` differs from the first `agent_id` observed by this
    /// Sidecar process. Enforces single-agent tenancy (V1 ADR §2).
    #[error("tenant mismatch")]
    TenantMismatch,
    /// Agent attempted a direct connection to a loopback address that is not a
    /// sanctioned Firma endpoint. Blocked at the sandbox boundary before it
    /// could reach a local admin port, daemon, or MCP server. The connection
    /// never traverses the proxy, so it is reported out-of-band by the
    /// `firma run` egress guard rather than the enforcement hot path.
    #[error("loopback blocked")]
    LoopbackBlocked,
    /// AARM R4 `STEP_UP`: the call is blocked pending human approval or
    /// stronger authentication before it may proceed. The agent should
    /// request approval and retry with the resulting approval credential.
    #[error("step up required")]
    StepUpRequired,
    /// AARM R4 `DEFER`: the call is blocked and should be retried after the
    /// supplied backoff window, pending additional context.
    #[error("deferred")]
    Deferred,
}

/// Errors that can arise when parsing or applying a [`ModificationSpec`].
#[derive(Debug, thiserror::Error)]
pub enum ModificationError {
    /// The `@modify` annotation value was empty.
    #[error("modify annotation value must not be empty")]
    EmptyValue,
    /// The header name in `redact_header:<name>` was empty.
    #[error("redact_header: header name must not be empty")]
    EmptyHeaderName,
    /// The header name could not be parsed as a valid HTTP header name.
    #[error("invalid header name `{raw}`: {source}")]
    InvalidHeaderName {
        raw: String,
        #[source]
        source: http::header::InvalidHeaderName,
    },
    /// The `@modify` kind was not recognised.
    #[error("unknown @modify kind; expected `redact_header:<name>`, got: {value:?}")]
    UnknownKind { value: String },
    /// The transformation targets HTTP headers, but the envelope's action
    /// params are not HTTP (e.g. `ToolUse`, `DbQuery`). Failing closed
    /// ensures the operator knows the policy doesn't match the traffic shape.
    #[error("modification targets HTTP headers but the action is not HTTP")]
    UnsupportedModificationTarget,
}

/// Structured transformation applied to a request under the AARM R4 `MODIFY`
/// decision.
///
/// Sourced from a `@modify("…")` Cedar policy annotation. The annotation
/// value is a small DSL: `<kind>:<value>`. V1 supports a single kind:
///
/// - `redact_header:<name>` — strip the named HTTP header (case-insensitive)
///   from the outbound request before dispatch. The audit record carries
///   `redacted_header:<name>` so an operator can reconcile the transformed
///   execution against policy intent.
///
/// `redact_header` strips the header from the agent-produced request. It does
/// **not** prevent the sidecar's credential-injection stage from adding the
/// same header back to the outbound request — the redaction is scoped to
/// what the agent sent, not to what the sidecar injects.
///
/// Unknown kinds, empty header names, or an invalid header name reject the
/// bundle at load time — the author must fix the policy. New kinds (e.g.
/// `strip_query_param`) can be added later as enum variants without a wire
/// break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModificationSpec {
    /// Strip the named HTTP header from the outbound request before dispatch.
    /// Header-name matching is case-insensitive (HTTP semantics).
    RedactHeader(HeaderName),
}

impl serde::Serialize for ModificationSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::RedactHeader(name) => serializer.serialize_newtype_variant(
                "ModificationSpec",
                0,
                "RedactHeader",
                name.as_str(),
            ),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ModificationSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        #[expect(non_snake_case, reason = "serde variant field name must match the tag")]
        enum Helper {
            RedactHeader { RedactHeader: String },
        }
        let helper = Helper::deserialize(deserializer)?;
        match helper {
            Helper::RedactHeader { RedactHeader: s } => {
                let name =
                    HeaderName::from_bytes(s.as_bytes()).map_err(serde::de::Error::custom)?;
                Ok(Self::RedactHeader(name))
            }
        }
    }
}

/// DSL prefix for the header-redaction transformation.
const MODIFICATION_REDACT_HEADER: &str = "redact_header:";

impl ModificationSpec {
    /// Parse a `@modify("…")` annotation value into a [`ModificationSpec`].
    ///
    /// # Errors
    ///
    /// - Empty value → [`ModificationError::EmptyValue`].
    /// - `redact_header:` with an empty name → [`ModificationError::EmptyHeaderName`].
    /// - Invalid header name → [`ModificationError::InvalidHeaderName`].
    /// - Unknown kind → [`ModificationError::UnknownKind`].
    pub fn parse(annotation: &str) -> Result<Self, ModificationError> {
        let value = annotation.trim();
        if value.is_empty() {
            return Err(ModificationError::EmptyValue);
        }
        if let Some(name) = value.strip_prefix(MODIFICATION_REDACT_HEADER) {
            let name = name.trim();
            if name.is_empty() {
                return Err(ModificationError::EmptyHeaderName);
            }
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|source| {
                ModificationError::InvalidHeaderName {
                    raw: name.to_string(),
                    source,
                }
            })?;
            return Ok(Self::RedactHeader(header_name));
        }
        Err(ModificationError::UnknownKind {
            value: value.to_string(),
        })
    }

    /// Apply this transformation in place to a dispatch-bound envelope.
    ///
    /// Mutates only the HTTP headers map of the dispatch clone; the original
    /// envelope stored on the sidecar's `EnforcementDecision::Modify` is
    /// untouched, preserving the immutability invariant.
    ///
    /// # Errors
    ///
    /// Returns [`ModificationError::UnsupportedModificationTarget`] if the
    /// envelope's action params are not HTTP — the policy author asked for
    /// header redaction on a non-HTTP target, which is a misconfiguration.
    /// Failing closed ensures the operator knows the policy doesn't match
    /// the traffic shape.
    pub fn apply(
        &self,
        envelope: &mut crate::envelope::ExecutionEnvelope,
    ) -> Result<(), ModificationError> {
        let crate::envelope::ActionParams::Http(http) = &mut envelope.intent.params else {
            return Err(ModificationError::UnsupportedModificationTarget);
        };
        match self {
            Self::RedactHeader(name) => {
                http.headers.remove(name);
            }
        }
        Ok(())
    }
}

impl std::fmt::Display for ModificationSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RedactHeader(name) => write!(f, "redacted_header:{name}"),
        }
    }
}

/// Human-readable challenge description for an AARM R4 `STEP_UP` decision.
///
/// Validates at construction that the value is not empty or whitespace-only,
/// so any value that survives into a [`crate::DenyReason::StepUpRequired`] or
/// a `PolicyVerdict::StepUp` is guaranteed to carry a meaningful message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepUpSpec(String);

impl StepUpSpec {
    /// Construct a [`StepUpSpec`] from a challenge string.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the value is empty or whitespace-only.
    pub fn new(value: impl Into<String>) -> Result<Self, ModificationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ModificationError::EmptyValue);
        }
        Ok(Self(value))
    }

    /// Return the challenge description as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StepUpSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for StepUpSpec {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Backoff duration for an AARM R4 `DEFER` decision.
///
/// Validates at construction that the duration is strictly positive, so any
/// value that survives into a `PolicyVerdict::Defer` is guaranteed to carry a
/// non-zero retry window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeferDuration(Duration);

impl DeferDuration {
    /// Construct a [`DeferDuration`] from a [`Duration`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the duration is zero.
    pub fn new(duration: Duration) -> Result<Self, ModificationError> {
        if duration.is_zero() {
            return Err(ModificationError::EmptyValue);
        }
        Ok(Self(duration))
    }

    /// Return the inner [`Duration`].
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl From<DeferDuration> for Duration {
    fn from(value: DeferDuration) -> Self {
        value.0
    }
}

/// Mode of a secret-mediation directive, from the `@mode(...)` annotation on a
/// `secret.mediate` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretMode {
    /// Wrap a vault CLI: capture its stdout, extract the secret(s), and mint
    /// placeholders (populates the dictionary).
    Intercept,
    /// Wrap a target tool: rehydrate placeholders on stdin and mask secrets on
    /// stdout (consumes the dictionary).
    Redact,
}

impl SecretMode {
    /// Parse a `@mode(...)` annotation value.
    ///
    /// # Errors
    ///
    /// Returns [`SecretMediationError::UnknownMode`] for an unrecognised value.
    pub fn parse(value: &str) -> Result<Self, SecretMediationError> {
        match value.trim() {
            "intercept" => Ok(Self::Intercept),
            "redact" => Ok(Self::Redact),
            other => Err(SecretMediationError::UnknownMode(other.to_string())),
        }
    }
}

/// Stream transform for a redact directive, from the `@transform(...)`
/// annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecretTransform {
    /// Streaming byte matcher for unstructured tools.
    #[serde(rename = "raw")]
    Raw,
    /// Newline-delimited JSON-RPC codec for MCP stdio servers.
    #[serde(rename = "mcp-jsonrpc")]
    McpJsonRpc,
}

impl SecretTransform {
    /// Parse a `@transform(...)` annotation value.
    ///
    /// # Errors
    ///
    /// Returns [`SecretMediationError::UnknownTransform`] for an unrecognised
    /// value.
    pub fn parse(value: &str) -> Result<Self, SecretMediationError> {
        match value.trim() {
            "raw" => Ok(Self::Raw),
            "mcp-jsonrpc" => Ok(Self::McpJsonRpc),
            other => Err(SecretMediationError::UnknownTransform(other.to_string())),
        }
    }
}

/// Errors from assembling a [`SecretMediation`] from policy annotations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretMediationError {
    /// `@mode` was absent.
    #[error("@mode annotation is required on a secret.mediate policy")]
    MissingMode,
    /// `@mode` value was not recognised.
    #[error("unknown @mode `{0}`; expected `intercept` or `redact`")]
    UnknownMode(String),
    /// `@transform` value was not recognised.
    #[error("unknown @transform `{0}`; expected `raw` or `mcp-jsonrpc`")]
    UnknownTransform(String),
    /// `@placeholder` was absent.
    #[error("@placeholder annotation is required on a secret.mediate policy")]
    MissingPlaceholder,
    /// `@mode("redact")` requires a `@transform`.
    #[error("@mode(\"redact\") requires a @transform annotation")]
    MissingTransform,
    /// `@mode("intercept")` requires an `@adapter`.
    #[error("@mode(\"intercept\") requires an @adapter annotation")]
    MissingAdapter,
    /// `@adapter` value was empty.
    #[error("@adapter annotation must not be empty")]
    EmptyAdapter,
    /// `@transform` present but the mode is `intercept`.
    #[error("@transform is only valid with @mode(\"redact\")")]
    UnexpectedTransform,
    /// `@adapter` present but the mode is `redact`.
    #[error("@adapter is only valid with @mode(\"intercept\")")]
    UnexpectedAdapter,
    /// `@placeholder` template was malformed.
    #[error("invalid @placeholder `{value}`: {reason}")]
    InvalidPlaceholder {
        /// The offending template value.
        value: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// A validated secret-mediation directive assembled from a `secret.mediate`
/// policy's annotations.
///
/// Sourced from `@mode`, `@transform`, `@adapter`, and `@placeholder` on a
/// `permit` policy for the `secret.mediate` action, assembled and validated at
/// bundle load; the broker copies it out per launch. See
/// `docs/architecture/secrets-interception.md`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretMediation {
    /// Interception mode.
    pub mode: SecretMode,
    /// Stream transform; `Some` if and only if `mode == Redact`.
    pub transform: Option<SecretTransform>,
    /// Vault-output adapter name; `Some` if and only if `mode == Intercept`.
    pub adapter: Option<String>,
    /// Placeholder template, e.g. `firma-secret://bitwarden/{name}`.
    pub placeholder: String,
}

/// Scheme every placeholder token begins with. Must match
/// `firma_run::secret::PLACEHOLDER_SCHEME`.
const PLACEHOLDER_TEMPLATE_SCHEME: &str = "firma-secret://";
/// Marker in a placeholder template substituted with the secret key at mint.
const PLACEHOLDER_NAME_MARKER: &str = "{name}";

impl SecretMediation {
    /// Assemble and validate a directive from raw annotation values.
    ///
    /// Each argument is the raw annotation value, or `None` if the annotation
    /// is absent.
    ///
    /// # Errors
    ///
    /// Returns the first [`SecretMediationError`] encountered: a missing or
    /// unknown `@mode`; a missing or malformed `@placeholder`; or a
    /// mode/`@transform`/`@adapter` combination that is inconsistent — `redact`
    /// needs `@transform` and rejects `@adapter`, while `intercept` needs a
    /// non-empty `@adapter` and rejects `@transform`.
    pub fn from_annotations(
        mode: Option<&str>,
        transform: Option<&str>,
        adapter: Option<&str>,
        placeholder: Option<&str>,
    ) -> Result<Self, SecretMediationError> {
        let mode = SecretMode::parse(mode.ok_or(SecretMediationError::MissingMode)?)?;
        let placeholder = placeholder.ok_or(SecretMediationError::MissingPlaceholder)?;
        validate_placeholder_template(placeholder)?;

        let transform = transform.map(SecretTransform::parse).transpose()?;
        let adapter = adapter.map(|value| value.trim().to_string());

        match mode {
            SecretMode::Redact => {
                if adapter.is_some() {
                    return Err(SecretMediationError::UnexpectedAdapter);
                }
                let transform = transform.ok_or(SecretMediationError::MissingTransform)?;
                Ok(Self {
                    mode,
                    transform: Some(transform),
                    adapter: None,
                    placeholder: placeholder.to_string(),
                })
            }
            SecretMode::Intercept => {
                if transform.is_some() {
                    return Err(SecretMediationError::UnexpectedTransform);
                }
                let adapter = adapter.ok_or(SecretMediationError::MissingAdapter)?;
                if adapter.is_empty() {
                    return Err(SecretMediationError::EmptyAdapter);
                }
                Ok(Self {
                    mode,
                    transform: None,
                    adapter: Some(adapter),
                    placeholder: placeholder.to_string(),
                })
            }
        }
    }
}

fn validate_placeholder_template(template: &str) -> Result<(), SecretMediationError> {
    let invalid = |reason: &str| SecretMediationError::InvalidPlaceholder {
        value: template.to_string(),
        reason: reason.to_string(),
    };
    if !template.starts_with(PLACEHOLDER_TEMPLATE_SCHEME) {
        return Err(invalid("must start with `firma-secret://`"));
    }
    if !template.contains(PLACEHOLDER_NAME_MARKER) {
        return Err(invalid("must contain the `{name}` marker"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Display;

    #[test]
    fn secret_mode_parse_accepts_known_and_rejects_unknown() {
        assert_eq!(SecretMode::parse("intercept"), Ok(SecretMode::Intercept));
        assert_eq!(SecretMode::parse("  redact  "), Ok(SecretMode::Redact));
        assert_eq!(
            SecretMode::parse("bogus"),
            Err(SecretMediationError::UnknownMode("bogus".to_string()))
        );
    }

    #[test]
    fn secret_transform_parse_accepts_known_and_rejects_unknown() {
        assert_eq!(SecretTransform::parse("raw"), Ok(SecretTransform::Raw));
        assert_eq!(
            SecretTransform::parse("mcp-jsonrpc"),
            Ok(SecretTransform::McpJsonRpc)
        );
        assert_eq!(
            SecretTransform::parse("json"),
            Err(SecretMediationError::UnknownTransform("json".to_string()))
        );
    }

    #[test]
    fn secret_mediation_redact_requires_transform_and_rejects_adapter() {
        let directive = SecretMediation::from_annotations(
            Some("redact"),
            Some("mcp-jsonrpc"),
            None,
            Some("firma-secret://bitwarden/{name}"),
        )
        .expect("valid redact directive");
        assert_eq!(directive.mode, SecretMode::Redact);
        assert_eq!(directive.transform, Some(SecretTransform::McpJsonRpc));
        assert_eq!(directive.adapter, None);

        assert_eq!(
            SecretMediation::from_annotations(
                Some("redact"),
                None,
                None,
                Some("firma-secret://x/{name}")
            ),
            Err(SecretMediationError::MissingTransform)
        );
        assert_eq!(
            SecretMediation::from_annotations(
                Some("redact"),
                Some("raw"),
                Some("bws"),
                Some("firma-secret://x/{name}")
            ),
            Err(SecretMediationError::UnexpectedAdapter)
        );
    }

    #[test]
    fn secret_mediation_intercept_requires_adapter_and_rejects_transform() {
        let directive = SecretMediation::from_annotations(
            Some("intercept"),
            None,
            Some("bws"),
            Some("firma-secret://bitwarden/{name}"),
        )
        .expect("valid intercept directive");
        assert_eq!(directive.mode, SecretMode::Intercept);
        assert_eq!(directive.adapter.as_deref(), Some("bws"));
        assert_eq!(directive.transform, None);

        assert_eq!(
            SecretMediation::from_annotations(
                Some("intercept"),
                None,
                None,
                Some("firma-secret://x/{name}")
            ),
            Err(SecretMediationError::MissingAdapter)
        );
        assert_eq!(
            SecretMediation::from_annotations(
                Some("intercept"),
                Some("raw"),
                Some("bws"),
                Some("firma-secret://x/{name}")
            ),
            Err(SecretMediationError::UnexpectedTransform)
        );
        assert_eq!(
            SecretMediation::from_annotations(
                Some("intercept"),
                None,
                Some("  "),
                Some("firma-secret://x/{name}")
            ),
            Err(SecretMediationError::EmptyAdapter)
        );
    }

    #[test]
    fn secret_mediation_requires_mode_and_well_formed_placeholder() {
        assert_eq!(
            SecretMediation::from_annotations(
                None,
                None,
                Some("bws"),
                Some("firma-secret://x/{name}")
            ),
            Err(SecretMediationError::MissingMode)
        );
        assert_eq!(
            SecretMediation::from_annotations(Some("intercept"), None, Some("bws"), None),
            Err(SecretMediationError::MissingPlaceholder)
        );
        // Wrong scheme and missing `{name}` marker are both rejected.
        assert!(matches!(
            SecretMediation::from_annotations(
                Some("intercept"),
                None,
                Some("bws"),
                Some("https://x/{name}")
            ),
            Err(SecretMediationError::InvalidPlaceholder { .. })
        ));
        assert!(matches!(
            SecretMediation::from_annotations(
                Some("intercept"),
                None,
                Some("bws"),
                Some("firma-secret://x/no-marker")
            ),
            Err(SecretMediationError::InvalidPlaceholder { .. })
        ));
    }

    #[test]
    fn secret_mediation_serde_round_trip() {
        let directive = SecretMediation::from_annotations(
            Some("redact"),
            Some("mcp-jsonrpc"),
            None,
            Some("firma-secret://bitwarden/{name}"),
        )
        .expect("valid directive");
        let json = serde_json::to_string(&directive).expect("serialize");
        // The wire form uses the hyphenated transform name.
        assert!(json.contains("mcp-jsonrpc"));
        let restored: SecretMediation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(directive, restored);
    }

    #[test]
    fn test_decision_allow() {
        let d = Decision::Allow;
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn test_decision_deny() {
        let d = Decision::Deny {
            reason: DenyReason::PolicyDenied,
        };
        assert!(matches!(
            d,
            Decision::Deny {
                reason: DenyReason::PolicyDenied
            }
        ));
    }

    #[test]
    fn test_decision_abort() {
        let d = Decision::Abort {
            reason: "fatal error".to_string(),
        };
        assert!(matches!(d, Decision::Abort { .. }));
    }

    #[test]
    fn test_abort_reason_code_all_variants() {
        use strum::IntoEnumIterator;
        // Exhaustive match: a new `AbortReason` variant fails to compile
        // here until its canonical code is added, so the registry can
        // never silently drift.
        for reason in AbortReason::iter() {
            let expected = match reason {
                AbortReason::ConnectorTimeout => "CONNECTOR_TIMEOUT",
                AbortReason::ConnectorFailure => "CONNECTOR_FAILURE",
                AbortReason::ConnectorInvalidRequest => "CONNECTOR_INVALID_REQUEST",
                AbortReason::CredentialInjectionFailed => "CREDENTIAL_INJECTION_FAILED",
            };
            assert_eq!(reason.code(), expected);
        }
    }

    #[test]
    fn test_deny_reason_display_all_variants() {
        let cases = [
            (DenyReason::TokenInvalid, "token invalid"),
            (DenyReason::TokenExpired, "token expired"),
            (DenyReason::TokenRevoked, "token revoked"),
            (DenyReason::PolicyDenied, "policy denied"),
            (DenyReason::ScopeViolation, "scope violation"),
            (DenyReason::ToolNotInScope, "tool not in scope"),
            (DenyReason::MalformedRequest, "malformed request"),
            (DenyReason::AuthorityUnavailable, "authority unavailable"),
            (DenyReason::PolicyBundleStale, "policy bundle stale"),
            (DenyReason::PolicyBundleNotReady, "policy bundle not ready"),
            (
                DenyReason::RevocationCacheNotReady,
                "revocation cache not ready",
            ),
            (DenyReason::FailClosed, "fail closed"),
            (DenyReason::EnforcementTimeout, "enforcement timeout"),
            (
                DenyReason::CredentialInjectionFailed,
                "credential injection failed",
            ),
            (DenyReason::ConnectorTimeout, "connector timeout"),
            (DenyReason::ConnectorNetworkError, "connector network error"),
            (
                DenyReason::ConnectorInvalidRequest,
                "connector invalid request",
            ),
            (DenyReason::UnclassifiedIntent, "unclassified intent"),
            (DenyReason::TenantMismatch, "tenant mismatch"),
            (DenyReason::LoopbackBlocked, "loopback blocked"),
            (DenyReason::StepUpRequired, "step up required"),
            (DenyReason::Deferred, "deferred"),
        ];
        for (reason, expected) in cases {
            assert_eq!(reason.to_string(), expected);
        }
    }

    #[test]
    fn test_deny_reason_copy() {
        let reason = DenyReason::TokenExpired;
        let copied = reason;
        assert_eq!(reason, copied);
    }

    #[test]
    fn modification_spec_round_trip() {
        let spec = ModificationSpec::RedactHeader(HeaderName::from_static("authorization"));
        let json = serde_json::to_string(&spec).unwrap_or_else(|e| panic!("{e}"));
        let parsed: ModificationSpec =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(spec, parsed);
    }

    #[test]
    fn modification_spec_parse_redact_header() {
        let spec = ModificationSpec::parse("redact_header:authorization")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            spec,
            ModificationSpec::RedactHeader(HeaderName::from_static("authorization"))
        );
    }

    #[test]
    fn modification_spec_parse_trims_whitespace() {
        let spec = ModificationSpec::parse("  redact_header:  x-api-key  ")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            spec,
            ModificationSpec::RedactHeader(HeaderName::from_static("x-api-key"))
        );
    }

    #[test]
    fn modification_spec_parse_rejects_empty_header_name() {
        let err = ModificationSpec::parse("redact_header:").unwrap_err();
        assert!(
            matches!(err, ModificationError::EmptyHeaderName),
            "expected EmptyHeaderName, got {err:?}"
        );
    }

    #[test]
    fn modification_spec_parse_rejects_invalid_header_name() {
        // `redact_header:<invalid>` — header name with illegal characters
        // is rejected by http::HeaderName::from_bytes.
        let err = ModificationSpec::parse("redact_header:invalid header").unwrap_err();
        assert!(
            matches!(err, ModificationError::InvalidHeaderName { .. }),
            "expected InvalidHeaderName, got {err:?}"
        );
    }

    #[test]
    fn modification_spec_parse_rejects_unknown_kind() {
        let err = ModificationSpec::parse("rewrite_body:foo").unwrap_err();
        assert!(
            matches!(err, ModificationError::UnknownKind { .. }),
            "expected UnknownKind, got {err:?}"
        );
    }

    #[test]
    fn modification_spec_parse_rejects_empty_value() {
        let err = ModificationSpec::parse("   ").unwrap_err();
        assert!(
            matches!(err, ModificationError::EmptyValue),
            "expected EmptyValue, got {err:?}"
        );
    }

    #[test]
    fn modification_spec_display_redacted_header() {
        let spec = ModificationSpec::RedactHeader(HeaderName::from_static("authorization"));
        assert_eq!(spec.to_string(), "redacted_header:authorization");
    }

    #[test]
    fn modification_spec_apply_strips_header_case_insensitive() {
        use crate::envelope::{
            ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
            HttpParams,
        };

        let mut headers = std::collections::HashMap::new();
        headers.insert(
            firma_http::HeaderName::from_static("authorization"),
            "Bearer secret".to_string(),
        );
        headers.insert(
            firma_http::HeaderName::from_static("x-trace-id"),
            "abc".to_string(),
        );
        let mut envelope = ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "communication.external.send".to_string(),
                resource: std::collections::BTreeMap::new(),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::POST,
                    headers,
                    body: None,
                    query: std::collections::HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "POST /v1/chat".to_string(),
            },
            "raw-token".to_string(),
            ExecutionMetadata {
                session_id: "sess".parse().unwrap(),
                agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        );

        // Redact the Authorization header (case-insensitive match).
        ModificationSpec::RedactHeader(HeaderName::from_static("authorization"))
            .apply(&mut envelope)
            .unwrap_or_else(|e| panic!("{e}"));

        let ActionParams::Http(http) = &envelope.intent.params else {
            panic!("expected Http params");
        };
        assert!(
            !http
                .headers
                .contains_key(&HeaderName::from_static("authorization")),
            "Authorization should be stripped"
        );
        assert!(
            http.headers
                .contains_key(&HeaderName::from_static("x-trace-id")),
            "X-Trace-Id should survive the redaction"
        );
    }

    #[test]
    fn modification_spec_apply_fails_closed_on_non_http() {
        use crate::envelope::{
            ActionParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, ToolUseParams,
        };

        let envelope = ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "tool.use".to_string(),
                resource: std::collections::BTreeMap::new(),
                params: ActionParams::ToolUse(ToolUseParams {
                    tool_name: "search".to_string(),
                    input: std::collections::HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "tool:search".to_string(),
            },
            "raw-token".to_string(),
            ExecutionMetadata {
                session_id: "sess".parse().unwrap(),
                agent_id: "agt_01j0000000e008000000000001".parse().unwrap(),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        );

        // Applying a RedactHeader to a non-HTTP envelope fails closed.
        let mut envelope = envelope;
        let err = ModificationSpec::RedactHeader(HeaderName::from_static("authorization"))
            .apply(&mut envelope)
            .unwrap_err();
        assert!(
            matches!(err, ModificationError::UnsupportedModificationTarget),
            "expected UnsupportedModificationTarget, got {err:?}"
        );
    }

    #[test]
    fn step_up_spec_rejects_empty() {
        assert!(StepUpSpec::new("").is_err());
        assert!(StepUpSpec::new("   ").is_err());
        assert!(StepUpSpec::new("require admin approval").is_ok());
    }

    #[test]
    fn defer_duration_rejects_zero() {
        assert!(DeferDuration::new(Duration::ZERO).is_err());
        assert!(DeferDuration::new(Duration::from_millis(1)).is_ok());
    }

    #[test]
    fn step_up_required_and_deferred_display_and_serde() {
        assert_eq!(DenyReason::StepUpRequired.to_string(), "step up required");
        assert_eq!(DenyReason::Deferred.to_string(), "deferred");
        for json in [r#""StepUpRequired""#, r#""Deferred""#] {
            let parsed: DenyReason = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(
                parsed,
                DenyReason::StepUpRequired | DenyReason::Deferred
            ));
        }
    }

    #[test]
    fn test_decision_serde_round_trip() {
        let decisions = [
            Decision::Allow,
            Decision::Deny {
                reason: DenyReason::ScopeViolation,
            },
            Decision::Abort {
                reason: "panic".to_string(),
            },
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).unwrap_or_else(|e| panic!("{e}"));
            let parsed: Decision = serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(*d, parsed);
        }
    }

    #[test]
    fn test_decision_eq() {
        assert_eq!(Decision::Allow, Decision::Allow);
        assert_ne!(
            Decision::Allow,
            Decision::Deny {
                reason: DenyReason::PolicyDenied
            }
        );
    }

    #[test]
    fn test_deny_reason_is_display() {
        fn assert_display<T: Display>() {}
        assert_display::<DenyReason>();
    }

    #[test]
    fn test_abort_reason_is_display() {
        fn assert_display<T: Display>() {}
        assert_display::<AbortReason>();
    }

    #[test]
    fn decision_backward_compat_allow() {
        let json = r#""Allow""#;
        let parsed: Decision = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed, Decision::Allow);
    }

    #[test]
    fn decision_backward_compat_deny() {
        let json = r#"{"Deny":{"reason":"ScopeViolation"}}"#;
        let parsed: Decision = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed,
            Decision::Deny {
                reason: DenyReason::ScopeViolation,
            }
        );
    }

    #[test]
    fn decision_backward_compat_abort() {
        let json = r#"{"Abort":{"reason":"fatal"}}"#;
        let parsed: Decision = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            parsed,
            Decision::Abort {
                reason: "fatal".to_string(),
            }
        );
    }

    #[test]
    fn deny_reason_backward_compat() {
        use strum::IntoEnumIterator;
        for reason in DenyReason::iter() {
            let json = match reason {
                DenyReason::TokenInvalid => r#""TokenInvalid""#,
                DenyReason::TokenExpired => r#""TokenExpired""#,
                DenyReason::TokenRevoked => r#""TokenRevoked""#,
                DenyReason::PolicyDenied => r#""PolicyDenied""#,
                DenyReason::ScopeViolation => r#""ScopeViolation""#,
                DenyReason::ToolNotInScope => r#""ToolNotInScope""#,
                DenyReason::MalformedRequest => r#""MalformedRequest""#,
                DenyReason::AuthorityUnavailable => r#""AuthorityUnavailable""#,
                DenyReason::PolicyBundleStale => r#""PolicyBundleStale""#,
                DenyReason::PolicyBundleNotReady => r#""PolicyBundleNotReady""#,
                DenyReason::RevocationCacheNotReady => r#""RevocationCacheNotReady""#,
                DenyReason::FailClosed => r#""FailClosed""#,
                DenyReason::EnforcementTimeout => r#""EnforcementTimeout""#,
                DenyReason::CredentialInjectionFailed => r#""CredentialInjectionFailed""#,
                DenyReason::ConnectorTimeout => r#""ConnectorTimeout""#,
                DenyReason::ConnectorNetworkError => r#""ConnectorNetworkError""#,
                DenyReason::ConnectorInvalidRequest => r#""ConnectorInvalidRequest""#,
                DenyReason::UnclassifiedIntent => r#""UnclassifiedIntent""#,
                DenyReason::TenantMismatch => r#""TenantMismatch""#,
                DenyReason::LoopbackBlocked => r#""LoopbackBlocked""#,
                DenyReason::StepUpRequired => r#""StepUpRequired""#,
                DenyReason::Deferred => r#""Deferred""#,
            };
            let parsed: DenyReason = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, reason);
        }
    }
}
