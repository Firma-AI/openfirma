//! Typed, security-oriented primitives for the `OpenFirma` native login flow.

mod browser;
mod control_plane;
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
pub use control_plane::{
    CloseOutcome, ControlPlaneClient, ControlPlaneError, RecordedOutcome, ResolvedAgent, StartedRun,
};
pub use entropy::EntropyError;
pub use origin::{ControlPlaneOrigin, ControlPlaneOriginError, LoginCommand, OriginValidationMode};
pub use pkce::{AuthorizationAttempt, AuthorizationState, PkceChallenge, PkceVerifier};
pub use protocol::{
    AuthenticatedConnection, AuthorizationRequest, AuthorizationScope, AuthorizedTokenExchange,
    NativeAccessGrant, NativeTokenClient, NativeTokenError, TerminalAuthorizationRequest,
};
pub use redirect::{
    AuthorizationCode, CallbackLanding, CallbackTimeoutError, CallbackWaitTimeout,
    CompletedAuthorizationAttempt, LANDING_PATH, LoopbackCallbackError,
    LoopbackCallbackListenerError, LoopbackRedirectUri, PendingAuthorizationAttempt,
};
pub use refusal::LoginRefusal;
pub use session::{NativeSession, SessionAccess, SessionError};
