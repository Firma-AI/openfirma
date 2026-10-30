use thiserror::Error;

/// Why the Control Plane refused a login, from its RFC 6749 error code. Each
/// case says what the user can do next; codes the CLI cannot act on differently
/// are grouped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LoginRefusal {
    /// The user denied the login in the browser.
    #[error("the login was denied in the browser")]
    AccessDenied,
    /// Too many logins are in progress.
    #[error("the Control Plane has too many logins in progress; try again shortly")]
    TemporarilyUnavailable,
    /// The code expired, was already used, or does not belong to this login.
    #[error(
        "the login code expired, was already used, or does not match; run the same `firma login` command again"
    )]
    InvalidGrant,
    /// The access token was rejected, for example because it expired.
    #[error("the Control Plane rejected the access token")]
    InvalidToken,
    /// The Control Plane failed.
    #[error("the Control Plane failed to complete the login; try again")]
    ServerError,
    /// Any other refusal, such as a request this CLI version formed differently.
    #[error(
        "the Control Plane refused the login request; this firma version may not match the Control Plane"
    )]
    Other,
}

impl LoginRefusal {
    /// Classifies an RFC 6749 `error` code.
    pub(crate) fn from_code(code: &str) -> Self {
        match code {
            "access_denied" => Self::AccessDenied,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "invalid_grant" => Self::InvalidGrant,
            "invalid_token" => Self::InvalidToken,
            "server_error" => Self::ServerError,
            _ => Self::Other,
        }
    }
}
