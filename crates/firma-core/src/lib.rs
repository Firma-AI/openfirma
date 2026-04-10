// Firma Core — shared types, traits, and error types for the Firma workspace.

mod decision;
mod envelope;
mod policy;
mod token;

pub use decision::{Decision, DenyReason};
pub use envelope::{
    ActionParams, DbQueryParams, ExecutionContext, ExecutionEnvelope, ExecutionIntent,
    ExecutionMetadata, HttpMethod, HttpParams, ToolUseParams,
};
pub use policy::{EvaluationError, PolicyBundle, PolicyBundleStore, PolicyEvaluator};
pub use token::paseto::{PasetoV4Signer, PasetoV4Verifier};
pub use token::{
    CapabilityClaims, RevocationStore, TokenError, TokenSigner, TokenState, TokenVerifier,
};
