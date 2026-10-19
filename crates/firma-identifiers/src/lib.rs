//! Validated identifiers used across `OpenFirma`'s external interfaces.
//!
//! Firma-generated identifiers use `TypeID`s backed by RFC 9562 UUID values.
//! Most use UUID v7 for time ordering; approval tokens use UUID v4 for
//! unpredictability. [`SessionId`] also accepts caller-provided values because
//! sessions can be correlated with external runtimes.

#[macro_use]
mod helper;

mod agent_id;
mod approval_token_id;
mod audit_event_id;
mod membership_id;
mod sandbox_id;
mod session_id;
mod token_id;
mod workspace_id;

pub use agent_id::{AgentId, AgentIdParseError};
pub use approval_token_id::{ApprovalTokenId, ApprovalTokenIdParseError};
pub use audit_event_id::{AuditEventId, AuditEventIdParseError};
pub use membership_id::{MembershipId, MembershipIdParseError};
pub use sandbox_id::{SandboxId, SandboxIdParseError};
pub use session_id::{InvalidSessionIdError, SessionId};
pub use token_id::{TokenId, TokenIdParseError};
pub use workspace_id::{WorkspaceId, WorkspaceIdParseError};
