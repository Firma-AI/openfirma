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
//! | `SecretProvider` | `Firma::SecretProvider`| resolved provider name |
//!
//! # Injection safety
//!
//! [`FirmaEntityUid`] uses [`EntityUid::from_type_name_and_id`] rather than
//! string interpolation.  [`EntityId`] stores the id opaquely and never
//! re-parses it as Cedar syntax, so special characters in the id cannot break
//! out of the entity binding.  [`AgentId`] additionally enforces
//! `[a-zA-Z0-9_-]{1,128}` at construction time as a second defence layer.

use std::{fmt, path::PathBuf, sync::Arc};

use cedar_policy::{
    EntityId, EntityTypeName, EntityUid, PolicySet, Schema, SourceLocation, ValidationErrorKind,
    ValidationMode, Validator,
};

use crate::AgentId;

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
    location: SourceLocation<'static>,
    error_kind: ValidationErrorKind,
}

impl PolicyError {
    fn fmt_location(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(files), Some(range_start)) = (&self.files, self.location.range_start()) {
            let mut cur_index = 0;
            for file in &files.0 {
                if range_start >= cur_index && range_start <= cur_index + file.content.len() {
                    let (line, col) = file.content.bytes().take(range_start - cur_index).fold(
                        (1, 1),
                        |(line, col), char| {
                            if char == b'\n' {
                                (line + 1, 1)
                            } else {
                                (line, col + 1)
                            }
                        },
                    );

                    write!(
                        f,
                        "policy `{}` on {}:{}:{}",
                        self.location.policy_id(),
                        file.path.display(),
                        line,
                        col
                    )?;
                    return Ok(());
                }
                cur_index += file.content.len() + 1;
            }
        }

        fmt::Display::fmt(&self.location, f)
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // equivalent to write!("validation error on {}: {}", self.location, self.error_kind)
        f.write_str("validation error on ")?;
        self.fmt_location(f)?;
        f.write_str(": ")?;
        self.error_kind.fmt(f)
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
/// # Errors
///
/// Returns `Err(messages)` with one entry per validation error when the policy
/// set does not strictly type-check against `schema`. Validation warnings are
/// not treated as errors.
pub fn validate_policies(
    policies: &PolicySet,
    schema: &Schema,
    policy_files: Option<&PolicyFiles>,
) -> Result<(), ValidationError> {
    let result = Validator::new(schema.clone()).validate(policies, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(());
    }
    Err(ValidationError(
        result
            .validation_errors()
            .map(|err| {
                // override default error message to gain file:row:column format
                PolicyError {
                    files: policy_files.cloned(),
                    location: err.location().clone(),
                    error_kind: err.error_kind().clone(),
                }
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
    SecretProvider(String),
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
            FirmaEntityUid::SecretProvider(id) => ("Firma::SecretProvider", id),
        };
        let entity_type = type_name_str.parse::<EntityTypeName>()?;
        let entity_id = EntityId::new(id_string);
        Ok(Self::from_type_name_and_id(entity_type, entity_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentId;

    #[test]
    fn agent_uid_roundtrip() {
        let agent: AgentId = "agt_01j0000000e008000000000001".parse().unwrap();
        let uid = EntityUid::try_from(FirmaEntityUid::Agent(agent)).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Agent");
        assert_eq!(uid.id().as_ref(), "agt_01j0000000e008000000000001");
    }

    #[test]
    fn action_uid_roundtrip() {
        let uid = EntityUid::try_from(FirmaEntityUid::Action("read".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Action");
        assert_eq!(uid.id().as_ref(), "read");
    }

    #[test]
    fn resource_uid_roundtrip() {
        let uid = EntityUid::try_from(FirmaEntityUid::Resource("2001:db8::1".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Resource");
        assert_eq!(uid.id().as_ref(), "2001:db8::1");
    }

    #[test]
    fn secret_provider_uid_roundtrip() {
        let uid =
            EntityUid::try_from(FirmaEntityUid::SecretProvider("bitwarden".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::SecretProvider");
        assert_eq!(uid.id().as_ref(), "bitwarden");
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
        assert_eq!(uid.id().as_ref(), evil);
    }

    #[test]
    fn resource_injection_payload_stored_opaquely() {
        let evil = "bucket\"; permit(principal, action, resource); //";
        let uid = EntityUid::try_from(FirmaEntityUid::Resource(evil.to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Resource");
        assert_eq!(uid.id().as_ref(), evil);
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
        // `resource` is unconstrained, so the validator reports this error
        // against every entity type that can be a resource for some action
        // (Resource, SecretProvider) — in hashmap-iteration order, which is
        // not stable across runs, so sort before comparing.
        let mut actual = errors.0.iter().map(ToString::to_string).collect::<Vec<_>>();
        actual.sort();
        let mut expected = vec![
            "validation error on policy `policy1` on /my/file2.cedar:7:5: attribute `whatever` for entity type Firma::SecretProvider not found".to_string(),
            "validation error on policy `policy1` on /my/file2.cedar:7:5: attribute `whatever` for entity type Firma::Resource not found".to_string(),
        ];
        expected.sort();
        assert_eq!(actual, expected);
    }
}
