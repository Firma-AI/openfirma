// Firma Core — shared types, traits, and error types for the Firma workspace.

mod decision;
mod envelope;
mod error;
mod token;
mod traits;

pub use decision::{Decision, DenyReason};
pub use envelope::{
    DbQueryParams, ExecutionContext, ExecutionEnvelope, ExecutionIntent, HttpParams,
    RequestMetadata, ToolUseParams,
};
pub use error::{EvaluationError, TokenError};
pub use token::{CapabilityClaims, TokenState};
pub use traits::{
    PolicyBundle, PolicyBundleStore, PolicyEvaluator, RevocationStore, TokenSigner, TokenVerifier,
};
