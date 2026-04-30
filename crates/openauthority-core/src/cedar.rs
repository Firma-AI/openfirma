//! Cedar entity UID types shared between Authority and Sidecar.
//!
//! Encodes the three roles used in `OpenAuthority` policy evaluation and produces the
//! Cedar entity UID string via [`Display`]. Both the Authority (issuance) and
//! the Sidecar (enforcement) must use identical UID formats — keeping this
//! type in `openauthority-core` makes that contract explicit.
//!
//! # Entity UID conventions
//!
//! | Variant    | Cedar format                          |
//! |------------|---------------------------------------|
//! | `Agent`    | `OpenAuthority::Agent::"<id>"`                |
//! | `Action`   | `OpenAuthority::Action::"<id>"`               |
//! | `Resource` | `OpenAuthority::Resource::"<id>"`             |

use cedar_policy::EntityUid;

use crate::agent::AgentId;

/// A typed Cedar entity UID in the `OpenAuthority` namespace.
#[derive(Debug, Clone)]
pub enum OpenAuthorityEntityUid {
    Agent(AgentId),
    Action(String),
    Resource(String),
}

impl TryFrom<OpenAuthorityEntityUid> for EntityUid {
    type Error = cedar_policy::ParseErrors;

    /// # Errors
    ///
    /// Returns [`cedar_policy::ParseErrors`] if the id contains characters
    /// that make the Cedar entity UID string unparseable (e.g. unescaped
    /// quotes).
    fn try_from(uid: OpenAuthorityEntityUid) -> Result<Self, Self::Error> {
        let uid_str = match uid {
            OpenAuthorityEntityUid::Agent(id) => format!("OpenAuthority::Agent::\"{id}\""),
            OpenAuthorityEntityUid::Action(id) => format!("OpenAuthority::Action::\"{id}\""),
            OpenAuthorityEntityUid::Resource(id) => format!("OpenAuthority::Resource::\"{id}\""),
        };
        uid_str.parse::<EntityUid>()
    }
}
