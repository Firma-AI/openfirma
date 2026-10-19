use thiserror::Error;
use url::{Host, Url};

/// A validated origin for the Firma control plane.
///
/// This type accepts only a scheme, host, and optional port. It prevents an
/// operator-supplied value from carrying a path, credentials, query, or
/// fragment into an authorization or token endpoint URL.
#[derive(Debug, PartialEq, Eq)]
pub struct ControlPlaneOrigin(Url);

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
        let host = url.host().ok_or(ControlPlaneOriginError::MissingHost)?;
        let is_loopback_host = is_loopback_host(&host);
        validate_origin_shape(&url)?;
        validate_scheme_policy(&url, validation_mode, is_loopback_host)?;

        Ok(Self(url))
    }

    /// Return the validated URL backing this origin.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

fn validate_origin_shape(url: &Url) -> Result<(), ControlPlaneOriginError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ControlPlaneOriginError::UserInfo);
    }

    if url.path() != "/" {
        return Err(ControlPlaneOriginError::Path);
    }

    if url.query().is_some() {
        return Err(ControlPlaneOriginError::Query);
    }

    if url.fragment().is_some() {
        return Err(ControlPlaneOriginError::Fragment);
    }

    Ok(())
}

fn validate_scheme_policy(
    url: &Url,
    validation_mode: OriginValidationMode,
    is_loopback_host: bool,
) -> Result<(), ControlPlaneOriginError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if validation_mode == OriginValidationMode::DevelopmentLoopback => {
            if is_loopback_host {
                Ok(())
            } else {
                Err(ControlPlaneOriginError::DevelopmentHttpRequiresLoopback)
            }
        }
        "http" => Err(ControlPlaneOriginError::RequiresHttps),
        _ => Err(ControlPlaneOriginError::UnsupportedScheme),
    }
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
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
