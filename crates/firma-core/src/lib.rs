// Firma Core — shared types, traits, and error types for the Firma workspace.

pub mod action_class;
pub mod capability_seed;
pub mod cedar;
pub mod connector;
pub mod credential;
pub mod decision;
pub mod envelope;
pub mod policy;
pub mod run_audit;
pub mod token;
pub mod transport;

pub use action_class::{ActionClass, UnknownActionClass};
pub use capability_seed::CapabilitySeed;
pub use cedar::{FIRMA_SCHEMA, FirmaEntityUid, validate_policies};
pub use connector::{Connector, ConnectorError, ConnectorResponse};
pub use credential::InjectedCredentials;
pub use decision::{
    AbortReason, DeferDuration, DenyReason, ModificationError, ModificationSpec,
    SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher, SecretNameSource, StepUpSpec,
};
pub use envelope::{
    ActionParams, DbQueryParams, ExecutionEnvelope, ExecutionIntent, ExecutionMetadata, HttpMethod,
    HttpParams, ToolUseParams,
};
pub use policy::PolicyBundle;
pub use run_audit::{RunAuditEvent, RunAuditMessage};
pub use token::{CapabilityClaims, RevocationStore, TokenError, TokenSigner, TokenVerifier};
pub use transport::TransportView;
