//! Concrete Cedar policy evaluator for Sidecar Stage 2.
//!
//! Implements [`PolicyEvaluation`] by evaluating a compiled Cedar policy set
//! against the context produced by
//! [`ConstraintEnforcer::build_context`][super::constraint_enforcement::ConstraintEnforcer].
//!
//! Evaluation is fully local — no network calls. [`CedarPolicyEvaluator`] is
//! constructed from a [`PolicyBundle`] received from the Authority and tracks
//! freshness against the bundle TTL.
//!
//! # Entity UID conventions (must match Authority's service.rs)
//!
//! | Cedar role  | Format                               |
//! |-------------|--------------------------------------|
//! | `principal` | `Firma::Agent::"<agent_id>"`         |
//! | `action`    | `Firma::Action::"<action_class>"`    |
//! | `resource`  | `Firma::Resource::"<resource_uri>"`  |

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, Entity, EntityUid, PolicyId, PolicySet,
    Request, Response, RestrictedExpression, Schema,
};
use firma_core::AgentId;
use firma_core::policy::PolicyBundle;
use firma_core::{DeferDuration, FirmaEntityUid, ModificationSpec, SecretDecision, StepUpSpec};

use super::constraint_enforcement::{PolicyEvaluation, PolicyVerdict};

/// Errors produced by Cedar policy loading and evaluation.
#[derive(Debug, thiserror::Error)]
pub enum CedarEvaluatorError {
    #[error("policy bytes are not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    #[error("policy bundle contains no policy statements")]
    EmptyPolicies,

    #[error("policy bundle contains no entity schema; schema is required")]
    MissingSchema,

    #[error("failed to parse Cedar policies: {0}")]
    PolicyParse(#[source] cedar_policy::ParseErrors),

    #[error("failed to parse Cedar schema: {0}")]
    SchemaParse(#[source] Box<cedar_policy::HumanSchemaError>),

    #[error("invalid entity UID: {0}")]
    EntityUidParse(#[source] cedar_policy::ParseErrors),

    #[error("failed to build Cedar context: {0}")]
    ContextBuild(#[source] Box<cedar_policy::ContextJsonError>),

    /// `cedar_policy::RequestValidationError` is intentionally not re-exported
    /// by the cedar-policy crate (it contains internal types), so we erase it
    /// via `Box<dyn Error>` while preserving the source chain.
    #[error("failed to build Cedar request: {0}")]
    RequestBuild(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A `forbid` policy carried a remediation annotation (`@modify`,
    /// `@step_up`, `@defer`) whose value could not be interpreted. The bundle
    /// is rejected at load time so the caller retains the previous good
    /// snapshot; the operator gets an immediate, actionable error instead of a
    /// silent semantic divergence between the authored policy and the one
    /// actually enforced.
    #[error(
        "malformed @{annotation} annotation on policy `{policy_id}`: {reason} (raw: {raw_value})"
    )]
    MalformedAnnotation {
        policy_id: String,
        annotation: &'static str,
        raw_value: String,
        reason: String,
    },

    /// A `forbid` policy carried more than one remediation annotation
    /// (`@modify` / `@step_up` / `@defer`). The bundle is rejected at load
    /// time because the author's intent is ambiguous. Split into separate
    /// `forbid` policies if different remediations are wanted for different
    /// conditions.
    #[error("policy `{policy_id}` carries multiple remediation annotations: {annotations}")]
    ConflictingAnnotations {
        policy_id: String,
        annotations: String,
    },

    /// A `permit` policy carried a remediation annotation (`@modify` /
    /// `@step_up` / `@defer`). The bundle is rejected at load time because a
    /// `permit` cannot raise a deny, so a remediation annotation on it has no
    /// effect — the author almost certainly attached it to the wrong policy.
    #[error(
        "policy `{policy_id}` (permit) carries remediation annotation(s) that only apply to forbid policies: {annotations}"
    )]
    AnnotationOnPermit {
        policy_id: String,
        annotations: String,
    },

    /// The resource entity for a `secret.mediate` decision could not be built
    /// (attribute construction or schema conformance failed).
    #[error("failed to build secret-mediation resource entity: {0}")]
    EntityBuild(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Concrete Cedar policy evaluator for Sidecar Stage 2.
///
/// Constructed from a [`PolicyBundle`] received from the Authority via
/// `WatchPolicyBundle`. Tracks freshness against the bundle's `ttl_seconds`
/// and evaluates Cedar policies schema-lessly.
#[derive(Debug)]
pub struct CedarPolicyEvaluator {
    policy_set: PolicySet,
    schema: Schema,
    version: String,
    received_at: Instant,
    ttl_secs: u32,
    /// `forbid` policies carrying an AARM R4 remediation annotation
    /// (`@modify`, `@step_up`, `@defer`), keyed by `PolicyId`. Built once at
    /// load time so the hot path only reads `Response::diagnostics().reason()`
    /// and looks up the firing policy here.
    remediation: HashMap<PolicyId, Remediation>,
}

/// Remediation directive attached to a `forbid` policy via a Cedar
/// annotation. Drives the AARM R4 `MODIFY` / `STEP_UP` / `DEFER` verdicts.
#[derive(Debug, Clone)]
enum Remediation {
    /// `@modify("redact_header:<name>")` — strip the named HTTP header before
    /// dispatch. The annotation value is parsed into a [`ModificationSpec`] at
    /// load time so the hot path just copies it out.
    Modify(ModificationSpec),
    /// `@step_up("…")` — require human approval; the annotation value is
    /// validated as a non-empty [`StepUpSpec`] at load time.
    StepUp(StepUpSpec),
    /// `@defer("<ms>")` — delay execution; the annotation value is parsed
    /// into a [`DeferDuration`] at load time.
    Defer(DeferDuration),
}

/// Annotation keys recognised on `forbid` policies for AARM R4 remediation.
const ANNOTATION_MODIFY: &str = "modify";
const ANNOTATION_STEP_UP: &str = "step_up";
const ANNOTATION_DEFER: &str = "defer";

impl CedarPolicyEvaluator {
    /// Construct from a [`PolicyBundle`] received from the Authority.
    ///
    /// Parses the Cedar policy source in `bundle.policies`. Fails fast if
    /// the bytes are not valid UTF-8 or contain invalid Cedar syntax — this
    /// matches the Authority's own fail-fast loading behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEvaluatorError::InvalidUtf8`] if policy or schema bytes
    /// are not valid UTF-8, [`CedarEvaluatorError::PolicyParse`] if the Cedar
    /// policy source is syntactically invalid, or
    /// [`CedarEvaluatorError::SchemaParse`] if the Cedar schema is invalid.
    pub fn from_bundle(bundle: &PolicyBundle) -> Result<Self, CedarEvaluatorError> {
        let src = std::str::from_utf8(&bundle.policies)?;

        if src.trim().is_empty() {
            return Err(CedarEvaluatorError::EmptyPolicies);
        }

        let policy_set = src
            .parse::<PolicySet>()
            .map_err(CedarEvaluatorError::PolicyParse)?;

        if bundle.entity_schema.is_empty() {
            return Err(CedarEvaluatorError::MissingSchema);
        }
        let schema_src = std::str::from_utf8(&bundle.entity_schema)?;
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
            .map_err(|e| CedarEvaluatorError::SchemaParse(Box::new(e)))?;

        let remediation = build_remediation_map(&policy_set)?;

        Ok(Self {
            policy_set,
            schema,
            version: bundle.version.clone(),
            received_at: Instant::now(),
            ttl_secs: bundle.ttl_seconds,
            remediation,
        })
    }

    /// Evaluate the `secret.mediate` action for a shimmed launch.
    ///
    /// `provider_id` is the stable secret-provider integration identity (e.g.
    /// `"bitwarden"` for the `bws` binary), resolved by firma-run from its
    /// `secret_providers` config; it becomes both the `Firma::SecretProvider`
    /// entity's UID and its `resource.id` attribute. `argv` is the wrapped
    /// tool's launch command line; it is split into `resource.bin` (executable
    /// basename) and `resource.args` (space-joined rest) so policies can match
    /// a specific invocation, e.g. `resource.bin == "bws"`.
    ///
    /// On a Cedar `Allow` from any `permit` policy, returns
    /// [`SecretDecision::Permit`] — Cedar is pure auth; extraction behavior
    /// comes from the `IntegrationRegistry` in firma-run, not from annotations.
    /// Any non-`Allow` outcome is [`SecretDecision::Passthrough`].
    ///
    /// # Errors
    ///
    /// Returns a [`CedarEvaluatorError`] if the entity UIDs, context, resource
    /// entity, or Cedar request cannot be built. The broker treats an error as
    /// fail-closed (deny the launch).
    fn secret_decision(
        &self,
        principal: &AgentId,
        provider_id: &str,
        argv: &str,
        context: serde_json::Value,
    ) -> Result<SecretDecision, CedarEvaluatorError> {
        let principal_uid: EntityUid = FirmaEntityUid::Agent(*principal)
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let action_uid: EntityUid = FirmaEntityUid::Action("secret.mediate".to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let resource_uid: EntityUid = FirmaEntityUid::SecretProvider(provider_id.to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;

        let cedar_context = Context::from_json_value(context, Some((&self.schema, &action_uid)))
            .map_err(|e| CedarEvaluatorError::ContextBuild(Box::new(e)))?;

        // resource.id is the stable provider identity (mirrors the entity
        // UID); resource.bin (argv[0] basename) and resource.args
        // (space-joined argv[1..]) carry the per-invocation detail.
        let (raw_bin, raw_args) = argv.split_once(' ').unwrap_or((argv, ""));
        let bin = std::path::Path::new(raw_bin)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(raw_bin);
        let mut attrs = HashMap::new();
        attrs.insert(
            "id".to_string(),
            RestrictedExpression::new_string(provider_id.to_string()),
        );
        attrs.insert(
            "bin".to_string(),
            RestrictedExpression::new_string(bin.to_string()),
        );
        attrs.insert(
            "args".to_string(),
            RestrictedExpression::new_string(raw_args.to_string()),
        );
        let resource_entity = Entity::new(resource_uid.clone(), attrs, HashSet::new())
            .map_err(|e| CedarEvaluatorError::EntityBuild(Box::new(e)))?;
        let entities = Entities::from_entities([resource_entity], Some(&self.schema))
            .map_err(|e| CedarEvaluatorError::EntityBuild(Box::new(e)))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEvaluatorError::RequestBuild(Box::new(e)))?;

        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);
        if matches!(response.decision(), Decision::Allow) {
            return Ok(SecretDecision::Permit);
        }
        Ok(SecretDecision::Passthrough)
    }

    /// Evaluate the `secret.mediate` action for an intercepted HTTP vault
    /// response (the MITM counterpart of [`Self::secret_decision`]'s CLI
    /// shim origin — same action, same `SecretProvider` entity type).
    ///
    /// `provider_id` becomes the entity's id (mirrors the entity UID, as in
    /// the CLI origin); `host`/`path`/`method` are bound to
    /// `resource.host`/`resource.path`/`resource.method` in place of the CLI
    /// origin's `resource.bin`/`resource.args`.
    ///
    /// # Errors
    ///
    /// Returns a [`CedarEvaluatorError`] if the entity UIDs, context, resource
    /// entity, or Cedar request cannot be built. The Sidecar treats an error
    /// as fail-closed (no interception).
    fn secret_mediate_http_decision(
        &self,
        principal: &AgentId,
        provider_id: &str,
        host: &str,
        path: &str,
        method: &str,
        context: serde_json::Value,
    ) -> Result<SecretDecision, CedarEvaluatorError> {
        let principal_uid: EntityUid = FirmaEntityUid::Agent(*principal)
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let action_uid: EntityUid = FirmaEntityUid::Action("secret.mediate".to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let resource_uid: EntityUid = FirmaEntityUid::SecretProvider(provider_id.to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;

        let cedar_context = Context::from_json_value(context, Some((&self.schema, &action_uid)))
            .map_err(|e| CedarEvaluatorError::ContextBuild(Box::new(e)))?;

        let mut attrs = HashMap::new();
        attrs.insert(
            "id".to_string(),
            RestrictedExpression::new_string(provider_id.to_string()),
        );
        attrs.insert(
            "host".to_string(),
            RestrictedExpression::new_string(host.to_string()),
        );
        attrs.insert(
            "path".to_string(),
            RestrictedExpression::new_string(path.to_string()),
        );
        attrs.insert(
            "method".to_string(),
            RestrictedExpression::new_string(method.to_string()),
        );
        let resource_entity = Entity::new(resource_uid.clone(), attrs, HashSet::new())
            .map_err(|e| CedarEvaluatorError::EntityBuild(Box::new(e)))?;
        let entities = Entities::from_entities([resource_entity], Some(&self.schema))
            .map_err(|e| CedarEvaluatorError::EntityBuild(Box::new(e)))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEvaluatorError::RequestBuild(Box::new(e)))?;

        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);
        if matches!(response.decision(), Decision::Allow) {
            return Ok(SecretDecision::Permit);
        }
        Ok(SecretDecision::Passthrough)
    }

    /// Evaluate the `secret.redact` action for an outbound HTTP request.
    ///
    /// Binds `resource.id` (host), `resource.host`, `resource.path`, and
    /// `resource.method` so policies can match with `resource.host == "api.github.com"`.
    /// Returns `true` on Cedar `Allow`, `false` otherwise (passthrough).
    fn secret_redact_decision(
        &self,
        principal: &AgentId,
        host: &str,
        path: &str,
        method: &str,
        context: serde_json::Value,
    ) -> Result<bool, CedarEvaluatorError> {
        let principal_uid: EntityUid = FirmaEntityUid::Agent(*principal)
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let action_uid: EntityUid = FirmaEntityUid::Action("secret.redact".to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let resource_uid: EntityUid = FirmaEntityUid::Resource(host.to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;

        let cedar_context = Context::from_json_value(context, Some((&self.schema, &action_uid)))
            .map_err(|e| CedarEvaluatorError::ContextBuild(Box::new(e)))?;

        let mut attrs = HashMap::new();
        attrs.insert(
            "id".to_string(),
            RestrictedExpression::new_string(host.to_string()),
        );
        attrs.insert(
            "host".to_string(),
            RestrictedExpression::new_string(host.to_string()),
        );
        attrs.insert(
            "path".to_string(),
            RestrictedExpression::new_string(path.to_string()),
        );
        attrs.insert(
            "method".to_string(),
            RestrictedExpression::new_string(method.to_string()),
        );
        let resource_entity = Entity::new(resource_uid.clone(), attrs, HashSet::new())
            .map_err(|e| CedarEvaluatorError::EntityBuild(Box::new(e)))?;
        let entities = Entities::from_entities([resource_entity], Some(&self.schema))
            .map_err(|e| CedarEvaluatorError::EntityBuild(Box::new(e)))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEvaluatorError::RequestBuild(Box::new(e)))?;

        let response = Authorizer::new().is_authorized(&request, &self.policy_set, &entities);
        Ok(matches!(response.decision(), Decision::Allow))
    }

    fn evaluate_response(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<Response, CedarEvaluatorError> {
        let principal_uid: EntityUid = FirmaEntityUid::Agent(*principal)
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let action_uid: EntityUid = FirmaEntityUid::Action(action.to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;
        let resource_uid: EntityUid = FirmaEntityUid::Resource(resource.to_string())
            .try_into()
            .map_err(CedarEvaluatorError::EntityUidParse)?;

        let cedar_context = Context::from_json_value(context, Some((&self.schema, &action_uid)))
            .map_err(|e| CedarEvaluatorError::ContextBuild(Box::new(e)))?;

        let request = Request::new(
            Some(principal_uid),
            Some(action_uid),
            Some(resource_uid),
            cedar_context,
            Some(&self.schema),
        )
        .map_err(|e| CedarEvaluatorError::RequestBuild(Box::new(e)))?;

        let entities = Entities::empty();
        Ok(Authorizer::new().is_authorized(&request, &self.policy_set, &entities))
    }
}

/// Scan the parsed `PolicySet` for remediation annotations and build a
/// `PolicyId -> Remediation` map for `forbid` policies.
///
/// Validation is fail-fast at load time:
/// - A `permit` policy carrying any remediation annotation is rejected
///   (`AnnotationOnPermit`): a permit cannot raise a deny, so the annotation
///   is a misconfiguration.
/// - A `forbid` policy carrying more than one annotation is rejected
///   (`ConflictingAnnotations`): the cross-policy precedence does not apply
///   within a single policy.
/// - A `@modify` or `@step_up` value that is empty or whitespace-only is
///   rejected (`MalformedAnnotation`): these carry human-readable
///   descriptions, and an empty value is a misconfiguration.
/// - A `@defer` value that is not a `u64` or is zero is rejected
///   (`MalformedAnnotation`).
///
/// On any of these errors the caller (`apply_bundle`) keeps the previous
/// good snapshot active, so the operator gets an immediate, actionable error
/// rather than a silent semantic divergence between the authored policy and
/// the one actually enforced.
fn build_remediation_map(
    policy_set: &PolicySet,
) -> Result<HashMap<PolicyId, Remediation>, CedarEvaluatorError> {
    let mut map = HashMap::new();
    for policy in policy_set.policies() {
        let id = policy.id().clone();
        let is_forbid = policy.effect() == Effect::Forbid;
        let modify = policy.annotation(ANNOTATION_MODIFY).map(str::to_string);
        let step_up = policy.annotation(ANNOTATION_STEP_UP).map(str::to_string);
        let defer = policy.annotation(ANNOTATION_DEFER).map(str::to_string);
        let present: Vec<&'static str> = [
            modify.as_ref().map(|_| ANNOTATION_MODIFY),
            step_up.as_ref().map(|_| ANNOTATION_STEP_UP),
            defer.as_ref().map(|_| ANNOTATION_DEFER),
        ]
        .into_iter()
        .flatten()
        .collect();

        if present.is_empty() {
            continue;
        }

        // Remediation annotations only make sense on `forbid` policies: a
        // `permit` cannot raise a deny, so a remediation annotation on it is a
        // misconfiguration. Reject the bundle so the operator removes it.
        if !is_forbid {
            return Err(CedarEvaluatorError::AnnotationOnPermit {
                policy_id: id.to_string(),
                annotations: present.join(", "),
            });
        }

        // At most one annotation per `forbid` policy: the cross-policy
        // precedence (`StepUp > Defer > Modify`) does not apply within a
        // single policy, so multiple annotations would resolve by implicit
        // check order rather than the documented semantics.
        if present.len() > 1 {
            return Err(CedarEvaluatorError::ConflictingAnnotations {
                policy_id: id.to_string(),
                annotations: present.join(", "),
            });
        }

        // Exactly one annotation — validate its value.
        if let Some(value) = modify {
            let spec = ModificationSpec::parse(&value).map_err(|err| {
                CedarEvaluatorError::MalformedAnnotation {
                    policy_id: id.to_string(),
                    annotation: ANNOTATION_MODIFY,
                    raw_value: value,
                    reason: err.to_string(),
                }
            })?;
            map.insert(id, Remediation::Modify(spec));
        } else if let Some(value) = step_up {
            let spec = StepUpSpec::new(value.clone()).map_err(|err| {
                CedarEvaluatorError::MalformedAnnotation {
                    policy_id: id.to_string(),
                    annotation: ANNOTATION_STEP_UP,
                    raw_value: value,
                    reason: err.to_string(),
                }
            })?;
            map.insert(id, Remediation::StepUp(spec));
        } else if let Some(value) = defer {
            match value.parse::<u64>() {
                Ok(0) => {
                    return Err(CedarEvaluatorError::MalformedAnnotation {
                        policy_id: id.to_string(),
                        annotation: ANNOTATION_DEFER,
                        raw_value: value,
                        reason: "defer duration must be > 0".to_string(),
                    });
                }
                Ok(ms) => match DeferDuration::new(Duration::from_millis(ms)) {
                    Ok(d) => {
                        map.insert(id, Remediation::Defer(d));
                    }
                    Err(err) => {
                        return Err(CedarEvaluatorError::MalformedAnnotation {
                            policy_id: id.to_string(),
                            annotation: ANNOTATION_DEFER,
                            raw_value: value,
                            reason: err.to_string(),
                        });
                    }
                },
                Err(parse_err) => {
                    return Err(CedarEvaluatorError::MalformedAnnotation {
                        policy_id: id.to_string(),
                        annotation: ANNOTATION_DEFER,
                        raw_value: value,
                        reason: parse_err.to_string(),
                    });
                }
            }
        }
    }
    Ok(map)
}

/// Precedence when multiple remediation annotations fire on the same Deny.
/// `StepUp` wins over `Defer` over `Modify`: a request needing human
/// approval should not be silently transformed or merely delayed, and a
/// deferred request should not be silently transformed in the meantime.
fn pick_remediation(candidates: &[&Remediation]) -> Option<Remediation> {
    /// Priority rank: higher wins. `None` filters out the non-remediation
    /// arms (which can't appear here, but keeps the lookup total).
    fn rank(r: &Remediation) -> u8 {
        match r {
            Remediation::StepUp(_) => 3,
            Remediation::Defer(_) => 2,
            Remediation::Modify(_) => 1,
        }
    }
    candidates.iter().copied().max_by_key(|r| rank(r)).cloned()
}

impl PolicyEvaluation for CedarPolicyEvaluator {
    /// Evaluate the `secret.mediate` action for a shimmed launch, exposing the
    /// internal logic through the trait with a stringified error for the
    /// swap-boundary surface.
    fn evaluate_secret_mediation(
        &self,
        principal: &AgentId,
        provider_id: &str,
        argv: &str,
        context: serde_json::Value,
    ) -> Result<SecretDecision, String> {
        self.secret_decision(principal, provider_id, argv, context)
            .map_err(|error| error.to_string())
    }

    /// Evaluate the `secret.mediate` action for an intercepted HTTP vault
    /// response, exposing the internal logic through the trait with a
    /// stringified error for the swap-boundary surface.
    fn evaluate_secret_mediate_http(
        &self,
        principal: &AgentId,
        provider_id: &str,
        host: &str,
        path: &str,
        method: &str,
        context: serde_json::Value,
    ) -> Result<SecretDecision, String> {
        self.secret_mediate_http_decision(principal, provider_id, host, path, method, context)
            .map_err(|error| error.to_string())
    }

    /// Evaluate whether to apply secret rewriting for an outbound HTTP request
    /// (`secret.redact`). Returns `true` when a Cedar `permit` fires.
    fn evaluate_secret_redact(
        &self,
        principal: &AgentId,
        host: &str,
        path: &str,
        method: &str,
        context: serde_json::Value,
    ) -> Result<bool, String> {
        self.secret_redact_decision(principal, host, path, method, context)
            .map_err(|error| error.to_string())
    }

    /// Evaluate Cedar policies for the given principal, action, and resource.
    ///
    /// Context attributes — the fields declared by `EnforcementContext` in
    /// the canonical `crates/firma-core/firma.cedarschema` — are built from
    /// the JSON object produced by `ConstraintEnforcer::build_context`.
    /// See the schema for the authoritative field list.
    ///
    /// Entity UIDs are constructed via [`FirmaEntityUid`] to match the
    /// Authority's issuance evaluation. No schema validation is performed on
    /// the request — policies that reference unknown attributes will receive
    /// Cedar's default deny.
    ///
    /// # Errors
    ///
    /// Returns [`CedarEvaluatorError::EntityUidParse`] if any entity UID is
    /// unparseable, [`CedarEvaluatorError::ContextBuild`] if the context JSON
    /// is invalid for the action's schema, or [`CedarEvaluatorError::RequestBuild`]
    /// if the Cedar request fails schema validation.
    fn evaluate(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<bool, String> {
        self.evaluate_response(principal, action, resource, context)
            .map(|response| matches!(response.decision(), Decision::Allow))
            .map_err(|e| e.to_string())
    }

    /// Cedar-aware override that surfaces AARM R4 remediation outcomes.
    ///
    /// On a Cedar `Deny`, scans `Response::diagnostics().reason()` for the
    /// `forbid` policy IDs that fired and looks each up in the pre-built
    /// remediation map. If a firing policy carries a
    /// `@modify` / `@step_up` / `@defer` annotation, the deny is lifted into a
    /// `MODIFY` / `STEP_UP` / `DEFER` verdict (precedence `StepUp > Defer >
    /// Modify` when several fire). Otherwise the deny is a hard
    /// [`PolicyVerdict::Deny`]. A Cedar `Allow` (or default-deny with no
    /// firing remediation policy) maps to `Allow` / `Deny` respectively.
    fn evaluate_verdict(
        &self,
        principal: &AgentId,
        action: &str,
        resource: &str,
        context: serde_json::Value,
    ) -> Result<PolicyVerdict, String> {
        let response = self
            .evaluate_response(principal, action, resource, context)
            .map_err(|e| e.to_string())?;
        match response.decision() {
            Decision::Allow => Ok(PolicyVerdict::Allow),
            Decision::Deny => {
                let candidates: Vec<&Remediation> = response
                    .diagnostics()
                    .reason()
                    .filter_map(|id| self.remediation.get(id))
                    .collect();
                Ok(match pick_remediation(&candidates) {
                    Some(Remediation::Modify(spec)) => PolicyVerdict::Modify {
                        modifications: spec,
                    },
                    Some(Remediation::StepUp(spec)) => PolicyVerdict::StepUp { challenge: spec },
                    Some(Remediation::Defer(spec)) => PolicyVerdict::Defer {
                        backoff: spec.duration(),
                    },
                    None => PolicyVerdict::Deny,
                })
            }
        }
    }

    fn is_fresh(&self) -> bool {
        self.received_at.elapsed().as_secs() < u64::from(self.ttl_secs)
    }

    fn version(&self) -> Option<String> {
        Some(self.version.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_core::policy::PolicyBundle;
    use serde_json::json;

    const TEST_SCHEMA: &str = "
namespace Firma {
    type EnforcementContext = {
        session_id: String,
        timestamp_ms: Long,
        params: String,
        risk_score: Long,
        session_duration_s: Long,
        action_count: Long,
        git_provider?: String,
        git_owner?: String,
        git_repo?: String,
        git_ref?: String,
        git_ref_type?: String,
        git_operation?: String
    };
    entity Agent;
    entity Resource { id: String, host?: String, path?: String, method?: String };
    entity SecretProvider { id: String, bin?: String, args?: String, host?: String, path?: String, method?: String };
    action \"communication.external.send\" appliesTo { principal: [Agent], resource: [Resource], context: EnforcementContext };
    action \"code.write\" appliesTo { principal: [Agent], resource: [Resource], context: EnforcementContext };
    action \"secret.mediate\" appliesTo { principal: [Agent], resource: [SecretProvider], context: EnforcementContext };
    action \"secret.redact\" appliesTo { principal: [Agent], resource: [Resource], context: EnforcementContext };
}";

    fn schema_bundle(policy_src: &[u8]) -> PolicyBundle {
        PolicyBundle::new(
            "schema-v1".to_string(),
            policy_src.to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn full_context() -> serde_json::Value {
        json!({
            "session_id": "sess_001",
            "timestamp_ms": 1_700_000_000_000i64,
            "params": "{}",
            "risk_score": 0i64,
            "session_duration_s": 0i64,
            "action_count": 1i64,
        })
    }

    fn permit_all_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "test-v1".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn forbid_all_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "test-v2".to_string(),
            b"forbid(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn empty_bundle() -> PolicyBundle {
        PolicyBundle::new("test-v0".to_string(), vec![], vec![], 30)
    }

    fn test_context() -> serde_json::Value {
        json!({
            "session_id": "sess_001",
            "timestamp_ms": 1_700_000_000_000i64,
            "params": "{}",
            "risk_score": 0i64,
            "session_duration_s": 0i64,
            "action_count": 1i64,
        })
    }

    fn agent() -> AgentId {
        "agt_01j0000000e008000000000001"
            .parse()
            .expect("valid agent id")
    }

    fn secret_bundle(policy_src: &str) -> PolicyBundle {
        PolicyBundle::new(
            "secret-v1".to_string(),
            policy_src.as_bytes().to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    #[test]
    fn evaluate_secret_mediation_returns_permit_on_matching_policy() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id == "bitwarden" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();
        let decision = evaluator
            .evaluate_secret_mediation(&agent(), "bitwarden", "bws secret get abc", full_context())
            .unwrap();
        assert_eq!(decision, SecretDecision::Permit);
    }

    #[test]
    fn evaluate_secret_mediation_passthrough_when_no_policy_matches() {
        let src = r#"
            @mode("intercept")
            @matcher("json")
            @match_value("$[*].value")
            @match_name("$[*].key")
            @placeholder("firma-secret://bitwarden/{name}")
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id == "bitwarden" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();
        let decision = evaluator
            .evaluate_secret_mediation(
                &agent(),
                "unmanaged",
                "curl https://example.com",
                full_context(),
            )
            .unwrap();
        assert_eq!(decision, SecretDecision::Passthrough);
    }

    #[test]
    fn secret_provider_id_reports_integration_name_not_argv() {
        // The entity id (and resource.id attribute) must be the resolved
        // provider identity, not the launch argv — even though the argv
        // contains a completely different string.
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id == "bitwarden" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();
        let decision = evaluator
            .evaluate_secret_mediation(&agent(), "bitwarden", "bws secret get abc", full_context())
            .unwrap();
        assert_eq!(decision, SecretDecision::Permit);

        // A policy matching on the argv-shaped legacy id no longer fires.
        let legacy_src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id like "bws *" };
        "#;
        let legacy_evaluator =
            CedarPolicyEvaluator::from_bundle(&secret_bundle(legacy_src)).unwrap();
        let legacy_decision = legacy_evaluator
            .evaluate_secret_mediation(&agent(), "bitwarden", "bws secret get abc", full_context())
            .unwrap();
        assert_eq!(legacy_decision, SecretDecision::Passthrough);
    }

    #[test]
    fn resource_bin_and_args_are_bound_for_secret_mediation() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.bin == "bws" && resource.args like "secret *" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();

        let permit = evaluator
            .evaluate_secret_mediation(&agent(), "bitwarden", "bws secret get abc", full_context())
            .unwrap();
        assert_eq!(permit, SecretDecision::Permit);

        let no_match = evaluator
            .evaluate_secret_mediation(&agent(), "bitwarden", "bws list", full_context())
            .unwrap();
        assert_eq!(no_match, SecretDecision::Passthrough);
    }

    #[test]
    fn evaluate_secret_mediate_http_returns_permit_on_matching_provider_id() {
        // Same action, same SecretProvider entity type as the CLI origin —
        // only the populated attributes differ (host/path/method vs bin/args).
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id == "aws-secrets-manager" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();
        let decision = evaluator
            .evaluate_secret_mediate_http(
                &agent(),
                "aws-secrets-manager",
                "secretsmanager.us-east-1.amazonaws.com",
                "/",
                "POST",
                full_context(),
            )
            .unwrap();
        assert_eq!(decision, SecretDecision::Permit);
    }

    #[test]
    fn evaluate_secret_mediate_http_passthrough_when_no_policy_matches() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.id == "aws-secrets-manager" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();
        let decision = evaluator
            .evaluate_secret_mediate_http(
                &agent(),
                "some-other-vault",
                "vault.example.com",
                "/",
                "GET",
                full_context(),
            )
            .unwrap();
        assert_eq!(decision, SecretDecision::Passthrough);
    }

    #[test]
    fn resource_host_path_method_are_bound_for_http_secret_mediation() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when {
                resource.host == "secretsmanager.us-east-1.amazonaws.com" &&
                resource.path == "/" &&
                resource.method == "POST"
            };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).unwrap();

        let permit = evaluator
            .evaluate_secret_mediate_http(
                &agent(),
                "aws-secrets-manager",
                "secretsmanager.us-east-1.amazonaws.com",
                "/",
                "POST",
                full_context(),
            )
            .unwrap();
        assert_eq!(permit, SecretDecision::Permit);

        let no_match = evaluator
            .evaluate_secret_mediate_http(
                &agent(),
                "aws-secrets-manager",
                "secretsmanager.us-east-1.amazonaws.com",
                "/",
                "GET",
                full_context(),
            )
            .unwrap();
        assert_eq!(no_match, SecretDecision::Passthrough);
    }

    #[test]
    fn evaluate_secret_redact_returns_true_on_matching_host_policy() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.redact", resource)
            when { resource.host == "api.github.com" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).expect("bundle");
        let result = evaluator
            .evaluate_secret_redact(
                &agent(),
                "api.github.com",
                "/user/repos",
                "GET",
                full_context(),
            )
            .expect("decision");
        assert!(result, "permit policy on host must return true");
    }

    #[test]
    fn evaluate_secret_redact_returns_false_when_host_does_not_match() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.redact", resource)
            when { resource.host == "api.github.com" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).expect("bundle");
        let result = evaluator
            .evaluate_secret_redact(
                &agent(),
                "attacker.example.com",
                "/steal",
                "POST",
                full_context(),
            )
            .expect("decision");
        assert!(!result, "no permit for non-matching host must return false");
    }

    #[test]
    fn evaluate_secret_redact_defaults_to_false_with_no_policy() {
        let src = r#"
            permit(principal, action == Firma::Action::"secret.mediate", resource)
            when { resource.bin == "bws" };
        "#;
        let evaluator = CedarPolicyEvaluator::from_bundle(&secret_bundle(src)).expect("bundle");
        let result = evaluator
            .evaluate_secret_redact(&agent(), "api.github.com", "/", "GET", full_context())
            .expect("decision");
        assert!(!result, "no secret.redact policy must default to false");
    }

    #[test]
    fn from_bundle_permit_all() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        assert_eq!(evaluator.version(), Some("test-v1".to_string()));
        assert!(evaluator.is_fresh());
    }

    #[test]
    fn from_bundle_empty_policies_deny() {
        // Empty policy bytes are rejected at construction time so the caller
        // can surface a typed error rather than silently falling through to
        // Cedar's default deny (which is indistinguishable from a legitimate
        // forbid-all bundle).
        let err = CedarPolicyEvaluator::from_bundle(&empty_bundle()).unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::EmptyPolicies),
            "expected EmptyPolicies, got {err}"
        );
    }

    #[test]
    fn from_bundle_invalid_syntax_fails_fast() {
        let bad = PolicyBundle::new(
            "bad".to_string(),
            b"this is not valid cedar {{{".to_vec(),
            vec![],
            30,
        );
        assert!(CedarPolicyEvaluator::from_bundle(&bad).is_err());
    }

    #[test]
    fn evaluate_permit_all_allows() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        let result = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                test_context(),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn evaluate_forbid_all_denies() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&forbid_all_bundle()).unwrap();
        let result = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                test_context(),
            )
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn is_fresh_with_30s_ttl() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        // Just constructed — should be fresh with 30s TTL.
        assert!(evaluator.is_fresh());
    }

    #[test]
    fn missing_schema_rejected() {
        let no_schema = PolicyBundle::new(
            "no-schema".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            vec![],
            30,
        );
        let err = CedarPolicyEvaluator::from_bundle(&no_schema).unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MissingSchema),
            "expected MissingSchema, got {err}"
        );
    }

    #[test]
    fn is_stale_with_zero_ttl() {
        let zero_ttl = PolicyBundle::new(
            "v0".to_string(),
            b"permit(principal, action, resource);".to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            0,
        );
        let evaluator = CedarPolicyEvaluator::from_bundle(&zero_ttl).unwrap();
        // TTL = 0 means immediately stale.
        assert!(!evaluator.is_fresh());
    }

    #[test]
    fn version_returned() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&permit_all_bundle()).unwrap();
        assert_eq!(evaluator.version(), Some("test-v1".to_string()));
    }

    #[test]
    fn context_attributes_accessible_in_policy() {
        // Policy referencing context.session_id — verifies context is wired through.
        let src =
            br#"permit(principal, action, resource) when { context.session_id == "sess_001" };"#;
        let bundle = PolicyBundle::new(
            "ctx-v1".to_string(),
            src.to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        );
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();

        let allow = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                test_context(),
            )
            .unwrap();
        assert!(allow);

        let deny_context = json!({
            "session_id": "different_session",
            "timestamp_ms": 1_700_000_000_000i64,
            "params": "{}",
            "risk_score": 0i64,
            "session_duration_s": 0i64,
            "action_count": 1i64,
        });
        let deny = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                deny_context,
            )
            .unwrap();
        assert!(!deny);
    }

    // ── Schema validation tests ───────────────────────────────────────────────

    #[test]
    fn schema_parses_from_bundle() {
        // schema is now mandatory — from_bundle succeeds only when schema bytes
        // are present; the field is Schema (not Option<Schema>).
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
    }

    #[test]
    fn schema_permit_all_allows_known_action() {
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let result = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                full_context(),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn schema_rejects_unknown_action() {
        // "unknown.action" is not declared in the schema — Request::new should fail.
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let result =
            evaluator.evaluate(&agent(), "unknown.action", "api.openai.com", full_context());
        assert!(
            result.is_err(),
            "unknown action must fail schema validation"
        );
    }

    #[test]
    fn schema_rejects_missing_context_field() {
        // Context missing required fields — Context::from_json_value should fail.
        let bundle = schema_bundle(b"permit(principal, action, resource);");
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let incomplete_context = json!({
            "session_id": "sess_001"
            // missing: timestamp_ms, params, risk_score
        });
        let result = evaluator.evaluate(
            &agent(),
            "communication.external.send",
            "api.openai.com",
            incomplete_context,
        );
        assert!(
            result.is_err(),
            "context missing required fields must fail schema validation"
        );
    }

    #[test]
    fn schema_context_attribute_used_in_policy() {
        // Policy referencing context.session_id — verifies context wiring with schema.
        let src =
            br#"permit(principal, action, resource) when { context.session_id == "sess_001" };"#;
        let bundle = schema_bundle(src);
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();

        let allow = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                full_context(),
            )
            .unwrap();
        assert!(allow);
    }

    #[test]
    fn schema_git_context_attributes_used_in_policy() {
        let src = br#"
            permit (
                principal == Firma::Agent::"agt_01j0000000e008000000000001",
                action == Firma::Action::"code.write",
                resource
            ) when {
                context.git_provider == "github" &&
                context.git_owner == "firma-ai" &&
                context.git_repo == "openfirma" &&
                context.git_ref == "refs/heads/fir-413" &&
                context.git_operation == "write"
            };
        "#;
        let bundle = schema_bundle(src);
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let mut context = full_context();
        context["git_provider"] = json!("github");
        context["git_owner"] = json!("firma-ai");
        context["git_repo"] = json!("openfirma");
        context["git_ref"] = json!("refs/heads/fir-413");
        context["git_ref_type"] = json!("branch");
        context["git_operation"] = json!("write");

        let allow = evaluator
            .evaluate(
                &agent(),
                "code.write",
                "github.com/firma-ai/openfirma.git/git-receive-pack",
                context.clone(),
            )
            .unwrap();
        assert!(allow);

        context["git_ref"] = json!("refs/heads/main");
        let deny = evaluator
            .evaluate(
                &agent(),
                "code.write",
                "github.com/firma-ai/openfirma.git/git-receive-pack",
                context,
            )
            .unwrap();
        assert!(!deny);
    }

    #[test]
    fn cedar_policy_denies_when_risk_score_exceeds_threshold() {
        let policy_src = br"
            forbid(principal, action, resource)
            when { context.risk_score > 50 };
            permit(principal, action, resource);
        ";
        let bundle = schema_bundle(policy_src);
        let evaluator = CedarPolicyEvaluator::from_bundle(&bundle).unwrap();
        let context = json!({
            "session_id": "sess_001",
            "timestamp_ms": 0i64,
            "params": "{}",
            "risk_score": 75i64,
            "session_duration_s": 0i64,
            "action_count": 1i64,
        });

        let allowed = evaluator
            .evaluate(
                &agent(),
                "communication.external.send",
                "api.openai.com/v1/chat/completions",
                context,
            )
            .unwrap();

        assert!(!allowed, "expected DENY when risk_score > threshold");
    }

    // ── Payment-splitting scenario (Layer 2 counter enforcement) ─────────────
    //
    // Scenario from Enforcement Memory Model §2:
    //   An agent attempts 6 × $2,000 transfers against a $10,000 daily limit.
    //   Transfers 1–5 are permitted (cumulative: $2k→$4k→$6k→$8k→$10k).
    //   Transfer 6 is denied: daily_cumulative_amount ($10,000) + transfer_amount
    //   ($2,000) = $12,000 exceeds the $10,000 daily cap.
    //
    // Run with: cargo test -p firma-sidecar payment_splitting

    const PAYMENT_SCHEMA: &str = r#"namespace Firma {
    entity Agent;
    entity Resource;
    type PaymentContext = {
        session_id: String,
        timestamp_ms: Long,
        params: String,
        risk_score: Long,
        session_duration_s: Long,
        action_count: Long,
        raw_transport: String,
        transfer_amount: Long,
        daily_cumulative_amount: Long,
        transfers_last_10m: Long,
        same_payee_count_30m: Long,
        session_transfer_count: Long
    };
    action "payment.transfer" appliesTo { principal: [Agent], resource: [Resource], context: PaymentContext };
    action "payment.purchase" appliesTo { principal: [Agent], resource: [Resource], context: PaymentContext };
}"#;

    // Daily cap: $10,000 (1_000_000 cents). Single-transfer ceiling: $5,000 (500_000 cents).
    // Payee concentration: < 3 per 30-minute window. Velocity: < 10 per 10-minute window.
    const PAYMENT_POLICY: &str = r#"
permit (
principal == Firma::Agent::"agt_01j0000000e008000000000001",
    action == Firma::Action::"payment.transfer",
    resource
) when {
    context.risk_score < 30 &&
    context.transfer_amount <= 500000 &&
    context.daily_cumulative_amount + context.transfer_amount <= 1000000 &&
    context.same_payee_count_30m < 3
};
forbid (principal, action == Firma::Action::"payment.transfer", resource)
    when { context.daily_cumulative_amount + context.transfer_amount > 1000000 };
forbid (principal, action == Firma::Action::"payment.transfer", resource)
    when { context.transfer_amount > 500000 };
forbid (principal, action == Firma::Action::"payment.transfer", resource)
    when { context.same_payee_count_30m >= 3 };
forbid (principal, action == Firma::Action::"payment.transfer", resource)
    when { context.transfers_last_10m >= 10 };
"#;

    #[derive(serde::Serialize)]
    struct PaymentCtx {
        session_id: &'static str,
        timestamp_ms: i64,
        params: &'static str,
        risk_score: i64,
        session_duration_s: i64,
        action_count: i64,
        raw_transport: &'static str,
        transfer_amount: i64,
        daily_cumulative_amount: i64,
        transfers_last_10m: i64,
        same_payee_count_30m: i64,
        session_transfer_count: i64,
    }

    impl Default for PaymentCtx {
        fn default() -> Self {
            Self {
                session_id: "sess-payment-split",
                timestamp_ms: 1_700_000_000_000,
                params: "{}",
                risk_score: 10,
                session_duration_s: 0,
                action_count: 1,
                raw_transport: "https",
                transfer_amount: 0,
                daily_cumulative_amount: 0,
                transfers_last_10m: 0,
                same_payee_count_30m: 0,
                session_transfer_count: 0,
            }
        }
    }

    fn payment_bundle() -> PolicyBundle {
        PolicyBundle::new(
            "payment-v1".to_string(),
            PAYMENT_POLICY.as_bytes().to_vec(),
            PAYMENT_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    #[test]
    fn payment_splitting_blocked_at_daily_limit() {
        // Transfers 1–5: each $2,000 (200_000 cents); cumulative goes
        // 0 → 200_000 → 400_000 → 600_000 → 800_000 → 1_000_000. All permitted.
        // Transfer 6: cumulative 1_000_000 + 200_000 = 1_200_000 > daily cap → denied.
        let evaluator = CedarPolicyEvaluator::from_bundle(&payment_bundle()).unwrap();
        let subject = agent();
        let resource = "payments.example.com";

        for i in 0..5i64 {
            let cumulative = i * 200_000;
            let ctx = serde_json::to_value(PaymentCtx {
                transfer_amount: 200_000,
                daily_cumulative_amount: cumulative,
                ..PaymentCtx::default()
            })
            .unwrap();
            let allowed = evaluator
                .evaluate(&subject, "payment.transfer", resource, ctx)
                .unwrap();
            assert!(
                allowed,
                "transfer {} (cumulative_before={cumulative} cents) should be permitted",
                i + 1
            );
        }

        // Transfer 6: daily_cumulative_amount already at cap.
        let ctx = serde_json::to_value(PaymentCtx {
            transfer_amount: 200_000,
            daily_cumulative_amount: 1_000_000,
            ..PaymentCtx::default()
        })
        .unwrap();
        let allowed = evaluator
            .evaluate(&subject, "payment.transfer", resource, ctx)
            .unwrap();
        assert!(
            !allowed,
            "transfer 6 must be denied: daily_cumulative_amount + transfer_amount > 1_000_000"
        );
    }

    #[test]
    fn payment_single_transfer_ceiling_enforced() {
        // A single $6,000 transfer (600_000 cents) exceeds the $5,000 ceiling.
        let evaluator = CedarPolicyEvaluator::from_bundle(&payment_bundle()).unwrap();
        let ctx = serde_json::to_value(PaymentCtx {
            transfer_amount: 600_000,
            ..PaymentCtx::default()
        })
        .unwrap();
        let allowed = evaluator
            .evaluate(&agent(), "payment.transfer", "payments.example.com", ctx)
            .unwrap();
        assert!(
            !allowed,
            "transfer exceeding single-transfer ceiling must be denied"
        );
    }

    #[test]
    fn payment_payee_concentration_enforced() {
        // 3 prior transfers to same payee in 30 minutes triggers the concentration forbid.
        let evaluator = CedarPolicyEvaluator::from_bundle(&payment_bundle()).unwrap();
        let ctx = serde_json::to_value(PaymentCtx {
            transfer_amount: 100_000,
            same_payee_count_30m: 3,
            ..PaymentCtx::default()
        })
        .unwrap();
        let allowed = evaluator
            .evaluate(&agent(), "payment.transfer", "payments.example.com", ctx)
            .unwrap();
        assert!(!allowed, "same-payee concentration >= 3 must be denied");
    }

    #[test]
    fn payment_transfer_permitted_within_all_limits() {
        // Clean state: $1,000 transfer, no prior activity. Should be permitted.
        let evaluator = CedarPolicyEvaluator::from_bundle(&payment_bundle()).unwrap();
        let ctx = serde_json::to_value(PaymentCtx {
            transfer_amount: 100_000,
            ..PaymentCtx::default()
        })
        .unwrap();
        let allowed = evaluator
            .evaluate(&agent(), "payment.transfer", "payments.example.com", ctx)
            .unwrap();
        assert!(allowed, "transfer within all limits must be permitted");
    }

    // ---- AARM R4 remediation annotation tests ----

    fn remediation_bundle(policy_src: &str) -> PolicyBundle {
        PolicyBundle::new(
            "remediation-v1".to_string(),
            policy_src.as_bytes().to_vec(),
            TEST_SCHEMA.as_bytes().to_vec(),
            30,
        )
    }

    fn verdict_for(evaluator: &CedarPolicyEvaluator) -> PolicyVerdict {
        evaluator
            .evaluate_verdict(
                &agent(),
                "communication.external.send",
                "api.openai.com",
                test_context(),
            )
            .unwrap_or_else(|e| panic!("evaluate_verdict failed: {e}"))
    }

    #[test]
    fn modify_annotation_lifts_deny_to_modify_verdict() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("redact_header:authorization")
forbid(principal, action, resource);"#,
        ))
        .unwrap();
        match verdict_for(&evaluator) {
            PolicyVerdict::Modify { modifications } => {
                assert_eq!(
                    modifications,
                    ModificationSpec::RedactHeader(http::HeaderName::from_static("authorization"))
                );
            }
            other => panic!("expected Modify, got {other:?}"),
        }
        // The bool view still reports a deny (Cedar's native decision).
        assert!(
            !evaluator
                .evaluate(
                    &agent(),
                    "communication.external.send",
                    "api.openai.com",
                    test_context(),
                )
                .unwrap()
        );
    }

    #[test]
    fn step_up_annotation_lifts_deny_to_step_up_verdict() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@step_up("require admin approval")
forbid(principal, action, resource);"#,
        ))
        .unwrap();
        match verdict_for(&evaluator) {
            PolicyVerdict::StepUp { challenge } => {
                assert_eq!(challenge.as_str(), "require admin approval");
            }
            other => panic!("expected StepUp, got {other:?}"),
        }
    }

    #[test]
    fn defer_annotation_lifts_deny_to_defer_verdict() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@defer("750")
forbid(principal, action, resource);"#,
        ))
        .unwrap();
        match verdict_for(&evaluator) {
            PolicyVerdict::Defer { backoff } => {
                assert_eq!(backoff, Duration::from_millis(750));
            }
            other => panic!("expected Defer, got {other:?}"),
        }
    }

    #[test]
    fn plain_forbid_without_annotation_stays_a_hard_deny() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&forbid_all_bundle()).unwrap();
        assert_eq!(verdict_for(&evaluator), PolicyVerdict::Deny);
    }

    #[test]
    fn malformed_defer_annotation_rejects_bundle() {
        // `@defer("not-a-number")` cannot parse to u64 ms; the bundle is
        // rejected at load time so the caller keeps the previous good
        // snapshot active rather than silently degrading to a plain deny.
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@defer("not-a-number")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MalformedAnnotation { .. }),
            "expected MalformedAnnotation, got {err}"
        );
    }

    #[test]
    fn zero_defer_duration_rejects_bundle() {
        // `@defer("0")` parses but is rejected: a defer with no backoff is
        // indistinguishable from a plain deny, so the author almost certainly
        // misconfigured the policy.
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@defer("0")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MalformedAnnotation { .. }),
            "expected MalformedAnnotation, got {err}"
        );
    }

    #[test]
    fn conflicting_annotations_reject_bundle() {
        // A single `forbid` policy carrying both `@modify` and `@step_up` is
        // ambiguous: the cross-policy precedence does not apply within one
        // policy, so the result would depend on implicit check order. The
        // bundle is rejected; the author must split into separate policies.
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("redact")
@step_up("admin")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::ConflictingAnnotations { .. }),
            "expected ConflictingAnnotations, got {err}"
        );
    }

    #[test]
    fn annotation_on_permit_rejects_bundle() {
        // A `permit` cannot raise a deny, so a remediation annotation on it
        // is a misconfiguration. The bundle is rejected at load time so the
        // operator removes the annotation or switches the effect to forbid.
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("on a permit")
permit(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::AnnotationOnPermit { .. }),
            "expected AnnotationOnPermit, got {err}"
        );
    }

    #[test]
    fn empty_modify_annotation_rejects_bundle() {
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MalformedAnnotation { .. }),
            "expected MalformedAnnotation, got {err}"
        );
    }

    #[test]
    fn unknown_modify_kind_rejects_bundle() {
        // `@modify("rewrite_body:foo")` parses but the kind is unknown; the
        // bundle is rejected at load time so the operator fixes the policy.
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("rewrite_body:foo")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MalformedAnnotation { .. }),
            "expected MalformedAnnotation, got {err}"
        );
    }

    #[test]
    fn empty_redact_header_name_rejects_bundle() {
        // `@modify("redact_header:")` has no header name; rejected at load
        // time because the transformation would be a no-op.
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("redact_header:")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MalformedAnnotation { .. }),
            "expected MalformedAnnotation, got {err}"
        );
    }

    #[test]
    fn whitespace_step_up_annotation_rejects_bundle() {
        let err = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@step_up("   ")
forbid(principal, action, resource);"#,
        ))
        .unwrap_err();
        assert!(
            matches!(err, CedarEvaluatorError::MalformedAnnotation { .. }),
            "expected MalformedAnnotation, got {err}"
        );
    }

    #[test]
    fn step_up_precedence_over_defer_and_modify() {
        // Three forbid policies fire on the same request, each with a
        // different remediation annotation. StepUp must win.
        let evaluator = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("redact_header:authorization")
forbid(principal, action, resource);
@defer("100")
forbid(principal, action, resource);
@step_up("s")
forbid(principal, action, resource);"#,
        ))
        .unwrap();
        assert!(matches!(
            verdict_for(&evaluator),
            PolicyVerdict::StepUp { .. }
        ));
    }

    #[test]
    fn defer_precedence_over_modify() {
        let evaluator = CedarPolicyEvaluator::from_bundle(&remediation_bundle(
            r#"@modify("redact_header:authorization")
forbid(principal, action, resource);
@defer("200")
forbid(principal, action, resource);"#,
        ))
        .unwrap();
        assert!(matches!(
            verdict_for(&evaluator),
            PolicyVerdict::Defer { .. }
        ));
    }
}
