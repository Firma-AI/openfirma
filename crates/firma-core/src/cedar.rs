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

use cedar_policy::EntityUid;

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
    /// Returns [`cedar_policy::ParseErrors`] if the id contains characters
    /// that make the Cedar entity UID string unparseable (e.g. unescaped
    /// quotes).
    fn try_from(uid: FirmaEntityUid) -> Result<Self, Self::Error> {
        let uid_str = match uid {
            FirmaEntityUid::Agent(id) => format!("Firma::Agent::\"{id}\""),
            FirmaEntityUid::Action(id) => format!("Firma::Action::\"{id}\""),
            FirmaEntityUid::Resource(id) => format!("Firma::Resource::\"{id}\""),
        };
        uid_str.parse::<EntityUid>()
    }
}
