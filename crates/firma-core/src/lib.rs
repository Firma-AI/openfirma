// Firma Core — shared types, traits, and error types for the Firma workspace.

pub mod action_class;
mod agent_id;
pub mod capability_seed;
pub mod cedar;
pub mod connector;
pub mod credential;
pub mod decision;
pub mod envelope;
pub mod policy;
pub mod run_audit;
pub mod session;
pub mod token;
pub mod transport;

pub use action_class::{ActionClass, UnknownActionClass};
#[doc(inline)]
pub use agent_id::AgentId;
pub use capability_seed::CapabilitySeed;
pub use cedar::{FIRMA_SCHEMA, FirmaEntityUid, validate_policies};
pub use connector::{Connector, ConnectorError, ConnectorResponse};
pub use credential::InjectedCredentials;
pub use decision::{
    AbortReason, DeferDuration, DenyReason, ModificationError, ModificationSpec,
    SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher, StepUpSpec,
};
pub use envelope::{
    ActionParams, DbQueryParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
    HttpParams, ToolUseParams,
};
pub use policy::PolicyBundle;
pub use run_audit::{RunAuditEvent, RunAuditMessage};
pub use session::SessionId;
pub use token::{
    CapabilityClaims, RevocationStore, TokenError, TokenId, TokenSigner, TokenVerifier,
};
pub use transport::TransportView;
