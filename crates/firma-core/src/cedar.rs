//! Cedar entity UID types shared between Authority and Sidecar.
//!
//! Encodes the three roles used in Firma policy evaluation and produces the
//! Cedar entity UID via [`TryFrom`] using Cedar's typed builder API.  Both
//! the Authority (issuance) and the Sidecar (enforcement) must use identical
//! UID formats — keeping this type in `firma-core` makes that contract
//! explicit.
//!
//! # Entity UID conventions
//!
//! | Variant    | Cedar type name    | ID source        |
//! |------------|--------------------|------------------|
//! | `Agent`    | `Firma::Agent`     | [`AgentId`]      |
//! | `Action`   | `Firma::Action`    | normalizer string |
//! | `Resource` | `Firma::Resource`  | normalizer string |
//!
//! # Injection safety
//!
//! [`FirmaEntityUid`] uses [`EntityUid::from_type_name_and_id`] rather than
//! string interpolation.  [`EntityId`] stores the id opaquely and never
//! re-parses it as Cedar syntax, so special characters in the id cannot break
//! out of the entity binding.  [`AgentId`] additionally enforces
//! `[a-zA-Z0-9_-]{1,128}` at construction time as a second defence layer.

use cedar_policy::{EntityId, EntityTypeName, EntityUid};

use crate::agent::AgentId;

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
        let (type_name_str, id_str): (&str, &str) = match &uid {
            FirmaEntityUid::Agent(id) => ("Firma::Agent", id.as_ref()),
            FirmaEntityUid::Action(id) => ("Firma::Action", id.as_str()),
            FirmaEntityUid::Resource(id) => ("Firma::Resource", id.as_str()),
        };
        let entity_type = type_name_str.parse::<EntityTypeName>()?;
        // EntityId::from_str is Infallible; the id is stored opaquely.
        let entity_id = id_str
            .parse::<EntityId>()
            .unwrap_or_else(|never| match never {});
        Ok(EntityUid::from_type_name_and_id(entity_type, entity_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentId;

    #[test]
    fn agent_uid_roundtrip() {
        let agent: AgentId = "agent-001".parse().unwrap();
        let uid = EntityUid::try_from(FirmaEntityUid::Agent(agent)).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Agent");
        assert_eq!(uid.id().as_ref(), "agent-001");
    }

    #[test]
    fn action_uid_roundtrip() {
        let uid = EntityUid::try_from(FirmaEntityUid::Action("read".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Action");
        assert_eq!(uid.id().as_ref(), "read");
    }

    #[test]
    fn resource_uid_roundtrip() {
        let uid = EntityUid::try_from(FirmaEntityUid::Resource("bucket-1".to_string())).unwrap();
        assert_eq!(uid.type_name().to_string(), "Firma::Resource");
        assert_eq!(uid.id().as_ref(), "bucket-1");
    }

    #[test]
    fn injection_payload_rejected_at_agent_id_construction() {
        let evil = r#"evil"; permit(principal, action, resource); //"#;
        assert!(evil.parse::<AgentId>().is_err());
    }

    #[test]
    fn injection_payload_rejected_quotes() {
        assert!(r#"agent"foo"#.parse::<AgentId>().is_err());
    }

    #[test]
    fn injection_payload_rejected_backslash() {
        assert!("agent\\foo".parse::<AgentId>().is_err());
    }

    #[test]
    fn injection_payload_rejected_semicolon() {
        assert!("agent;permit".parse::<AgentId>().is_err());
    }
}
