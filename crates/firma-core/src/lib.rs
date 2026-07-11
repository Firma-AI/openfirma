// Firma Core — shared types, traits, and error types for the Firma workspace.

pub mod agent;
pub mod capability_seed;
pub mod cedar;
pub mod connector;
pub mod credential;
pub mod decision;
pub mod envelope;
pub mod policy;
pub mod run_audit;
pub mod serde_header_name;
pub mod session;
pub mod token;
pub mod transport;

pub use agent::AgentId;
pub use capability_seed::CapabilitySeed;
pub use cedar::{FIRMA_SCHEMA, FirmaEntityUid, validate_policies};
pub use connector::{Connector, ConnectorError, ConnectorResponse};
pub use credential::InjectedCredentials;
pub use decision::{
    AbortReason, Decision, DeferDuration, DenyReason, ModificationError, ModificationSpec,
    StepUpSpec,
};
pub use envelope::{
    ActionParams, DbQueryParams, ExecutionContext, ExecutionEnvelope, ExecutionIntent,
    ExecutionMetadata, HttpMethod, HttpParams, ToolUseParams,
};
pub use policy::{EvaluationError, PolicyBundle, PolicyBundleStore, PolicyEvaluator};
pub use run_audit::{RunAuditEvent, RunAuditMessage};
pub use serde_header_name::HeaderName;
pub use session::SessionId;
pub use token::{
    CapabilityClaims, RevocationStore, TokenError, TokenId, TokenSigner, TokenVerifier,
};
pub use transport::TransportView;
