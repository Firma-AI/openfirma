//! Typed, security-oriented primitives for the `OpenFirma` native login flow.

mod browser;
mod entropy;
mod origin;
mod pkce;
mod protocol;
mod redirect;
mod refusal;
mod session;

/// Upper bound on an authorization code from either delivery mode. The
/// Authority owns the real format; this only refuses what no code can be.
const MAX_AUTHORIZATION_CODE_BYTES: usize = 512;

pub use browser::print_and_open;
pub use entropy::EntropyError;
pub use origin::{ControlPlaneOrigin, ControlPlaneOriginError, OriginValidationMode};
pub use pkce::{AuthorizationAttempt, AuthorizationState, PkceChallenge, PkceVerifier};
pub use protocol::{
    AuthenticatedConnection, AuthorizationRequest, AuthorizationScope, AuthorizedTokenExchange,
    NativeAccessGrant, NativeTokenClient, NativeTokenError, TerminalAuthorizationRequest,
};
pub use redirect::{
    AuthorizationCode, CallbackTimeoutError, CallbackWaitTimeout, CompletedAuthorizationAttempt,
    LoopbackCallbackError, LoopbackCallbackListenerError, LoopbackRedirectUri,
    PendingAuthorizationAttempt,
};
pub use refusal::LoginRefusal;
pub use session::{NativeSession, SessionError};
