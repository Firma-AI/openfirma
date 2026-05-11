//! Cedar entity UID types shared between Authority and Sidecar.
//!
//! Encodes the three roles used in Firma policy evaluation and produces the
//! Cedar entity UID string via [`Display`]. Both the Authority (issuance) and
//! the Sidecar (enforcement) must use identical UID formats — keeping this
//! type in `firma-core` makes that contract explicit.
//!
//! # Entity UID conventions
//!
//! | Variant    | Cedar format                          |
//! |------------|---------------------------------------|
//! | `Agent`    | `Firma::Agent::"<id>"`                |
//! | `Action`   | `Firma::Action::"<id>"`               |
//! | `Resource` | `Firma::Resource::"<id>"`             |
//!
//! # Security note on UID construction
//!
//! Cedar entity UIDs use the format `Namespace::Type::"<escaped_id>"`.
//! The embedded id must not contain unescaped quotes (`"`) or backslashes
//! (`\`) as these would break the UID parsing. The `try_into<EntityUid>`
//! conversion validates this before formatting.

use cedar_policy::EntityUid;

use crate::agent::AgentId;

/// Error when a Cedar UID component contains invalid characters.
#[derive(Debug, thiserror::Error)]
#[error("invalid cedar uid component: must not contain quotes or backslashes")]
pub struct InvalidCedarUidComponentError;

fn validate_cedar_uid_component(id: &str) -> Result<(), InvalidCedarUidComponentError> {
    if id.contains('"') || id.contains('\\') {
        return Err(InvalidCedarUidComponentError);
    }
    Ok(())
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
    /// Returns [`cedar_policy::ParseErrors`] if the id contains characters
    /// that make the Cedar entity UID string unparseable (e.g. unescaped
    /// quotes). Also returns an error if the id contains quote or backslash
    /// characters which are forbidden as they cannot be safely embedded.
    fn try_from(uid: FirmaEntityUid) -> Result<Self, Self::Error> {
        let uid_str = match uid {
            FirmaEntityUid::Agent(id) => {
                let s = id.as_ref();
                validate_cedar_uid_component(s).map_err(|_| cedar_policy::ParseErrors::new())?;
                format!("Firma::Agent::\"{s}\"")
            }
            FirmaEntityUid::Action(id) => {
                validate_cedar_uid_component(&id).map_err(|_| cedar_policy::ParseErrors::new())?;
                format!("Firma::Action::\"{id}\"")
            }
            FirmaEntityUid::Resource(id) => {
                validate_cedar_uid_component(&id).map_err(|_| cedar_policy::ParseErrors::new())?;
                format!("Firma::Resource::\"{id}\"")
            }
        };
        uid_str.parse::<EntityUid>()
    }
}
