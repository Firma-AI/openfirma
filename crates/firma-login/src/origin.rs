use std::fmt;

use firma_config_utils::http::{HttpOrigin, HttpUrlError, Https, HttpsOrLoopbackHttp};
use firma_connection_store::{Connection, OriginMode};
use thiserror::Error;
use url::Url;

/// A validated origin for the Firma control plane.
///
/// This type accepts only a scheme, host, and optional port. It prevents an
/// operator-supplied value from carrying a path, credentials, query, or
/// fragment into an authorization or token endpoint URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneOrigin(HttpOrigin<HttpsOrLoopbackHttp>);

impl ControlPlaneOrigin {
    /// Validate `url` as a control-plane origin for `validation_mode`.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not an HTTPS origin, or the explicit
    /// development exception is not an HTTP loopback origin.
    pub fn new(
        url: Url,
        validation_mode: OriginValidationMode,
    ) -> Result<Self, ControlPlaneOriginError> {
        let origin = match validation_mode {
            OriginValidationMode::Production => HttpOrigin::<Https>::new(url)?.into(),
            OriginValidationMode::DevelopmentLoopback => HttpOrigin::new(url)?,
        };
        Ok(Self(origin))
    }

    /// Validate the origin a saved connection names, under the mode its login
    /// validated it with.
    ///
    /// # Errors
    ///
    /// Returns an error when the saved origin no longer passes that mode.
    pub fn saved(connection: &Connection) -> Result<Self, ControlPlaneOriginError> {
        let mode = match connection.origin_mode {
            OriginMode::Production => OriginValidationMode::Production,
            OriginMode::DevelopmentLoopback => OriginValidationMode::DevelopmentLoopback,
        };
        Self::new(connection.origin.clone(), mode)
    }

    /// Return the validated URL backing this origin.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        self.0.as_url()
    }
}

/// The `firma login` command that logs in again to a saved connection's
/// Control Plane. A bare `firma login` targets the hosted one, so the origin
/// is always named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCommand {
    origin: String,
    development_loopback: bool,
}

impl LoginCommand {
    /// The command for the Control Plane and mode `connection` was saved with.
    #[must_use]
    pub(crate) fn saved(connection: &Connection) -> Self {
        Self {
            origin: connection.origin.origin().ascii_serialization(),
            development_loopback: connection.origin_mode == OriginMode::DevelopmentLoopback,
        }
    }
}

impl fmt::Display for LoginCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "firma login --control-plane-origin {}",
            self.origin
        )?;
        if self.development_loopback {
            formatter.write_str(" --development-loopback")?;
        }
        Ok(())
    }
}

/// The security policy used to validate a control-plane origin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OriginValidationMode {
    /// Require HTTPS for every control-plane origin.
    #[default]
    Production,

    /// Permit HTTP only when the host is a local loopback address or
    /// `localhost`.
    DevelopmentLoopback,
}

/// Why a candidate control-plane origin is unsuitable for native login.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlPlaneOriginError {
    /// The URL does not identify a host.
    #[error("control-plane origin must include a host")]
    MissingHost,

    /// The URL includes a user name or password.
    #[error("control-plane origin must not include user information")]
    UserInfo,

    /// The URL includes a non-root path.
    #[error("control-plane origin must not include a path")]
    Path,

    /// The URL includes a query string.
    #[error("control-plane origin must not include a query string")]
    Query,

    /// The URL includes a fragment.
    #[error("control-plane origin must not include a fragment")]
    Fragment,

    /// The URL uses HTTP outside the explicit local-development mode.
    #[error("control-plane origin must use HTTPS")]
    RequiresHttps,

    /// The URL uses development HTTP against a non-loopback host.
    #[error("development HTTP control-plane origins must target loopback")]
    DevelopmentHttpRequiresLoopback,

    /// The URL has a scheme other than HTTP or HTTPS.
    #[error("control-plane origin uses an unsupported scheme")]
    UnsupportedScheme,
}

impl From<HttpUrlError> for ControlPlaneOriginError {
    fn from(error: HttpUrlError) -> Self {
        match error {
            HttpUrlError::MissingHost => Self::MissingHost,
            HttpUrlError::Credentials => Self::UserInfo,
            HttpUrlError::Path => Self::Path,
            HttpUrlError::Query => Self::Query,
            HttpUrlError::Fragment => Self::Fragment,
            HttpUrlError::UnsupportedScheme => Self::UnsupportedScheme,
            HttpUrlError::RequiresHttps => Self::RequiresHttps,
            HttpUrlError::HttpRequiresLoopback => Self::DevelopmentHttpRequiresLoopback,
        }
    }
}
