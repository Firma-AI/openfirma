// Firma Core — shared types, traits, and error types for the Firma workspace.

mod connector;
mod credential;
mod decision;
mod envelope;
mod error;
mod paseto;
mod token;
mod traits;
mod transport;

pub use connector::{Connector, ConnectorError, ConnectorResponse};
pub use credential::InjectedCredentials;
pub use decision::{Decision, DenyReason};
pub use envelope::{
    ActionParams, DbQueryParams, ExecutionContext, ExecutionEnvelope, ExecutionIntent,
    ExecutionMetadata, HttpMethod, HttpParams, ToolUseParams,
};
pub use error::{EvaluationError, TokenError};
pub use paseto::{PasetoV4Signer, PasetoV4Verifier};
pub use token::{CapabilityClaims, TokenState};
pub use traits::{
    PolicyBundle, PolicyBundleStore, PolicyEvaluator, RevocationStore, TokenSigner, TokenVerifier,
};
pub use transport::TransportView;
