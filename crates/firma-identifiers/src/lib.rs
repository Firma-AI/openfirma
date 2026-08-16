//! Validated identifiers used across `OpenFirma`'s external interfaces.
//!
//! Firma-generated identifiers use `TypeID`s backed by RFC 9562 UUID v7 values.
//! [`SessionId`] also accepts caller-provided values because sessions can be
//! correlated with external runtimes.

#[macro_use]
mod helper;

mod agent_id;
mod approval_token_id;
mod audit_event_id;
mod sandbox_id;
mod session_id;
mod token_id;

pub use agent_id::{AgentId, AgentIdParseError};
pub use approval_token_id::{ApprovalTokenId, ApprovalTokenIdParseError};
pub use audit_event_id::{AuditEventId, AuditEventIdParseError};
pub use sandbox_id::{SandboxId, SandboxIdParseError};
pub use session_id::{InvalidSessionIdError, SessionId};
pub use token_id::{TokenId, TokenIdParseError};
