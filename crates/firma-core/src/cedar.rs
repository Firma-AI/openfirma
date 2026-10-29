//! Cedar entity UID types and shared schema for Firma policy evaluation.
//!
//! Encodes the entity roles used in Firma policy evaluation and produces the
//! Cedar entity UID via [`TryFrom`] using Cedar's typed builder API.  Both
//! the Authority (issuance) and the Sidecar (enforcement) must use identical
//! UID formats — keeping this type in `firma-core` makes that contract
//! explicit.
//!
//! # Entity UID conventions
//!
//! | Variant          | Cedar type name        | ID source          |
//! |------------------|------------------------|---------------------|
//! | `Agent`          | `Firma::Agent`         | [`AgentId`]         |
//! | `Action`         | `Firma::Action`        | normalizer string   |
//! | `Resource`       | `Firma::Resource`      | normalizer string   |
//!
//! # Injection safety
//!
//! [`FirmaEntityUid`] uses [`EntityUid::from_type_name_and_id`] rather than
//! string interpolation.  [`EntityId`] stores the id opaquely and never
//! re-parses it as Cedar syntax, so special characters in the id cannot break
//! out of the entity binding.  [`AgentId`] additionally enforces
//! `[a-zA-Z0-9_-]{1,128}` at construction time as a second defence layer.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use cedar_policy::{
    Entity, EntityAttrEvaluationError, EntityId, EntityTypeName, EntityUid, PolicySet,
    RestrictedExpression, Schema, ValidationMode, ValidationWarning, Validator,
};

use crate::ExecutionIntent;
use firma_identifiers::AgentId;

/// Canonical Firma Cedar schema, embedded at compile time.
///
/// This is the single source of truth for the Cedar schema shared between the
/// Authority (issuance) and the Sidecar (enforcement).  Operators who extend
/// the action registry can override the schema at runtime by configuring an
/// explicit `schema_path` in the Authority config.
// M-CANONICAL-DOCS: public constant with module-level docs above.
pub const FIRMA_SCHEMA: &str = include_str!("../firma.cedarschema");

#[derive(Debug, Clone)]
struct PolicyFile {
    path: PathBuf,
    content: Arc<str>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyFiles(Vec<PolicyFile>);

impl PolicyFiles {
    pub fn push(&mut self, path: PathBuf, content: String) {
        self.0.push(PolicyFile {
            path,
            content: content.into(),
        });
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn concat(&self) -> String {
        self.0
            .iter()
            .enumerate()
            .flat_map(|(index, file)| {
                "\n".chars()
                    .take(usize::from(index > 0))
                    .chain(file.content.chars())
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
struct PolicyError {
    files: Option<PolicyFiles>,
    /// A Cedar validation error, or a warning that [`validate_policies`]
    /// rejects.
    error: Box<dyn miette::Diagnostic + Send + Sync>,
}

impl PolicyError {
    /// Resolves the error's source label to `(path, line, column)` in the
    /// concatenated policy files, when both are known.
    fn location(&self) -> Option<(&Path, usize, usize)> {
        let files = self.files.as_ref()?;
        let range_start = self.error.labels()?.next()?.offset();
        let mut cur_index = 0;
        for file in &files.0 {
            if range_start >= cur_index && range_start <= cur_index + file.content.len() {
                let (line, col) = file.content.bytes().take(range_start - cur_index).fold(
                    (1, 1),
                    |(line, col), byte| {
                        if byte == b'\n' {
                            (line + 1, 1)
                        } else {
                            (line, col + 1)
                        }
                    },
                );
                return Some((&file.path, line, col));
            }
            cur_index += file.content.len() + 1;
        }
        None
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Cedar's message already names the policy; add the file location.
        match self.location() {
            Some((path, line, col)) => write!(
                f,
                "validation error on {}:{line}:{col}: {}",
                path.display(),
                self.error
            ),
            None => write!(f, "validation error: {}", self.error),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct ValidationError(Vec<PolicyError>);

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("policy bundle failed schema validation:")?;
        for error in &self.0 {
            f.write_str("\n")?;
            error.fmt(f)?;
        }
        Ok(())
    }
}

/// Strictly validate a parsed Cedar policy set against a schema.
///
/// Runs Cedar's strict validation and returns every validation error as a
/// human-readable string. An empty policy set is valid. The Authority's bundle
/// loader calls this to fail closed on an invalid bundle, applying the same
/// strict-validation contract that the offline `firma policy validate` CLI
/// enforces (the CLI runs the equivalent strict check separately so it can
/// render located miette diagnostics).
///
/// On success, returns Cedar's validation warnings, such as a policy that can
/// never apply, so the caller can report them.
///
/// # Errors
///
/// Returns `Err(messages)` with one entry per validation error when the policy
/// set does not strictly type-check against `schema`, or when a policy's scope
/// matches no action in the schema. Cedar reports the latter as an
/// `InvalidActionApplication` warning since 4.13; it is rejected so a policy
/// that can never apply fails loading, as it did before. Other validation
/// warnings are returned in `Ok`.
pub fn validate_policies(
    policies: &PolicySet,
    schema: &Schema,
    policy_files: Option<&PolicyFiles>,
) -> Result<Vec<String>, ValidationError> {
    let result = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    let (rejected, warnings): (Vec<_>, Vec<_>) = result
        .validation_warnings()
        .partition(|warning| matches!(warning, ValidationWarning::InvalidActionApplication(_)));
    if result.validation_passed() && rejected.is_empty() {
        return Ok(warnings.into_iter().map(ToString::to_string).collect());
    }
    let errors = result
        .validation_errors()
        .map(|err| Box::new(err.clone()) as Box<dyn miette::Diagnostic + Send + Sync>)
        .chain(
            rejected
                .into_iter()
                .map(|warning| Box::new(warning.clone()) as _),
        );
    Err(ValidationError(
        errors
            // override default error message to gain file:row:column format
            .map(|error| PolicyError {
                files: policy_files.cloned(),
                error,
            })
            .collect(),
    ))
}

/// A typed Cedar entity UID in the `Firma` namespace.
#[derive(Debug, Clone)]
pub enum FirmaEntityUid {
    Agent(AgentId),
    Action(String),
    Resource(String),
}

impl TryFrom<FirmaEntityUid> for EntityUid {
    type Error = cedar_policy::ParseErrors;

    /// # Errors
    ///
    /// Returns [`cedar_policy::ParseErrors`] if the entity type name string
    /// fails to parse (this should never happen for the static literals used
    /// here, but the error is propagated rather than panicked).
    fn try_from(uid: FirmaEntityUid) -> Result<Self, Self::Error> {
        let (type_name_str, id_string) = match uid {
            FirmaEntityUid::Agent(id) => ("Firma::Agent", id.to_string()),
            FirmaEntityUid::Action(id) => ("Firma::Action", id),
            FirmaEntityUid::Resource(id) => ("Firma::Resource", id),
        };
        let entity_type = type_name_str.parse::<EntityTypeName>()?;
        let entity_id = EntityId::new(id_string);
        Ok(Self::from_type_name_and_id(entity_type, entity_id))
    }
}

/// Failure building a resource [`Entity`] with attributes.
#[derive(Debug, thiserror::Error)]
pub enum ResourceEntityError {
    /// The resource UID string failed to parse into a Cedar entity type name.
    #[error("invalid resource entity uid: {0}")]
    Uid(#[source] Box<cedar_policy::ParseErrors>),
    /// Cedar rejected the resource entity's attribute record.
    #[error("invalid resource entity attributes: {0}")]
    Attr(#[source] Box<EntityAttrEvaluationError>),
}

impl FirmaEntityUid {
    /// Build a Cedar [`Entity`] for the request resource, populating the
    /// `id`, `host`, and `path` attributes declared by `Firma::Resource` in
    /// the canonical schema.
    ///
    /// Both the Authority (issuance) and the Sidecar (enforcement) call this
    /// so host-level Cedar rules (`resource.host == "…"`) evaluate identically
    /// on both sides. Without a populated resource entity in the authorizer's
    /// entity store, any `resource.<attr>` access errors and the guarded
    /// condition is skipped — so this is required for `resource.id` rules too,
    /// not only host/path.
    ///
    /// `resource` is the normalizer's display string (`"<host><path>"`, e.g.
    /// [`ExecutionIntent::resource_display`]). `host` and `path` are recovered
    /// from it via [`ExecutionIntent::resource_map_from`] and only emitted when
    /// non-empty, matching the `host?` / `path?` optional schema attributes.
    /// The id is stored opaquely (see the module-level injection-safety note).
    ///
    /// # Errors
    ///
    /// Returns [`ResourceEntityError::Uid`] if the resource UID cannot be
    /// parsed, or [`ResourceEntityError::Attr`] if Cedar rejects the attribute
    /// record.
    pub fn resource_entity(resource: &str) -> Result<Entity, ResourceEntityError> {
        let uid: EntityUid = Self::Resource(resource.to_string())
            .try_into()
            .map_err(|e| ResourceEntityError::Uid(Box::new(e)))?;
        let parts = ExecutionIntent::resource_map_from(resource);

        let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        attrs.insert(
            "id".to_string(),
            RestrictedExpression::new_string(resource.to_string()),
        );
        for key in ["host", "path"] {
            if let Some(value) = parts.get(key).filter(|v| !v.is_empty()) {
                attrs.insert(
                    key.to_string(),
                    RestrictedExpression::new_string(value.clone()),
                );
            }
        }

        Entity::new(uid, attrs, HashSet::new()).map_err(|e| ResourceEntityError::Attr(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_identifiers::AgentId;

    #[test]
    fn agent_uid_roundtrip() {
        let agent: AgentId = "agt_01j0000000e008000000000001".parse().unwrap();
        let uid = EntityUid::try_from(FirmaEntityUid::Agent(agent)).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Agent");
        assert_eq!(
            AsRef::<str>::as_ref(uid.id()),
            "agt_01j0000000e008000000000001"
        );
    }

    #[test]
    fn action_uid_roundtrip() {
        let uid = EntityUid::try_from(FirmaEntityUid::Action("read".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Action");
        assert_eq!(AsRef::<str>::as_ref(uid.id()), "read");
    }

    #[test]
    fn resource_uid_roundtrip() {
        let uid = EntityUid::try_from(FirmaEntityUid::Resource("2001:db8::1".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Resource");
        assert_eq!(AsRef::<str>::as_ref(uid.id()), "2001:db8::1");
    }

    // Action and Resource take raw strings (normalizer-controlled). The typed
    // builder stores the id opaquely — even a Cedar syntax payload cannot
    // break out of the entity binding.
    #[test]
    fn action_injection_payload_stored_opaquely() {
        let evil = r#"read"; permit(principal, action, resource); //"#;
        let uid = EntityUid::try_from(FirmaEntityUid::Action(evil.to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Action");
        // id stored verbatim, not interpreted as Cedar syntax
        assert_eq!(AsRef::<str>::as_ref(uid.id()), evil);
    }

    #[test]
    fn resource_injection_payload_stored_opaquely() {
        let evil = "bucket\"; permit(principal, action, resource); //";
        let uid = EntityUid::try_from(FirmaEntityUid::Resource(evil.to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Resource");
        assert_eq!(AsRef::<str>::as_ref(uid.id()), evil);
    }

    #[test]
    fn validate_policies_accepts_valid_set() {
        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA).unwrap();
        let set: PolicySet =
            "permit(principal, action == Firma::Action::\"filesystem.read\", resource);"
                .parse()
                .unwrap();
        assert!(validate_policies(&set, &schema, None).is_ok());
    }

    #[test]
    fn validate_policies_rejects_unknown_action() {
        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA).unwrap();
        let set: PolicySet = "forbid(principal, action == Firma::Action::\"foo.bar\", resource);"
            .parse()
            .unwrap();
        let errs = validate_policies(&set, &schema, None).expect_err("unknown action must fail");
        assert!(!errs.0.is_empty());
        assert!(
            errs.0.iter().any(|e| e.to_string().contains("foo.bar")),
            "error should name the unknown action; got: {errs:?}"
        );
    }

    #[test]
    fn validate_policies_returns_impossible_policy_warning() {
        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA).unwrap();
        let set: PolicySet = "forbid(principal, action == Firma::Action::\"filesystem.read\", resource) when { false };"
            .parse()
            .unwrap();
        let warnings = validate_policies(&set, &schema, None).unwrap();
        assert_eq!(
            warnings,
            [
                "for policy `policy0`, policy is impossible: the policy expression evaluates to false for all valid requests"
            ]
        );
    }

    #[test]
    fn validate_policies_rejects_scope_matching_no_action() {
        let policy = "permit(principal is Firma::Resource, action == Firma::Action::\"filesystem.read\", resource);";
        let mut files = PolicyFiles::default();
        files.push(PathBuf::from("/my/file.cedar"), policy.to_owned());
        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA).unwrap();
        let set: PolicySet = policy.parse().unwrap();

        let errors = validate_policies(&set, &schema, Some(&files)).unwrap_err();
        let actual = errors.0.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                "validation error on /my/file.cedar:1:1: for policy `policy0`, unable to find an applicable action given the policy scope constraints"
            ]
        );
    }

    #[test]
    fn validate_policies_accepts_empty_set() {
        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA).unwrap();
        assert!(validate_policies(&PolicySet::new(), &schema, None).is_ok());
    }

    #[test]
    fn test_error_location() {
        let policy1 = r#"// multibyte utf8 chars ßßß
forbid (
    principal,
    action,
    resource
) when {
    resource.id like "169.254.169.254*"
};
"#;
        let policy2 = r#"// multibyte utf8 chars ßßß
forbid (
    principal,
    action,
    resource
) when {
    resource.whatever like "169.254.169.254*"
};
"#;
        let mut files = PolicyFiles::default();
        files.push(PathBuf::from("/my/file1.cedar"), policy1.to_owned());
        files.push(PathBuf::from("/my/file2.cedar"), policy2.to_owned());

        let (schema, _) = Schema::from_cedarschema_str(FIRMA_SCHEMA).unwrap();
        let policies = files.concat().parse::<PolicySet>().unwrap();

        let errors = validate_policies(&policies, &schema, Some(&files)).unwrap_err();
        let actual = errors.0.iter().map(ToString::to_string).collect::<Vec<_>>();
        let expected = vec![
            "validation error on /my/file2.cedar:7:5: for policy `policy1`, attribute `whatever` on entity type `Firma::Resource` not found".to_string(),
        ];
        assert_eq!(actual, expected);
    }
}
