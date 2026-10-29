//! Validated HTTP(S) origins and URLs for configuration values.
//!
//! [`HttpOrigin`] and [`HttpUrl`] own the URL shape checks that configured
//! endpoints share: a host is present, and credentials, a query, and a fragment
//! are absent. The [`SchemePolicy`] type parameter decides which schemes are
//! acceptable, so a value typed `HttpOrigin<Https>` is known to be HTTPS
//! without the holder checking again.
//!
//! Checks run in a fixed order: host, credentials, path, query, fragment, then
//! scheme. A value with several problems therefore reports embedded
//! credentials first, before any other problem.

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::{Host, Url};

/// The schemes a validated URL may use.
///
/// This trait is sealed; the policies are [`Https`], [`HttpsOrLoopbackHttp`],
/// and [`HttpOrHttps`].
pub trait SchemePolicy: sealed::Sealed {
    /// Checks the scheme of a URL whose host is already known to be present.
    ///
    /// # Errors
    ///
    /// Returns [`HttpUrlError`] when this policy does not allow the scheme for
    /// that host.
    fn check(scheme: &str, host: &Host<&str>) -> Result<(), HttpUrlError>;
}

/// Requires HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Https {}

/// Requires HTTPS, except that HTTP is allowed when the host is `localhost`,
/// an IPv4 loopback address, or the IPv6 loopback address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpsOrLoopbackHttp {}

/// Allows HTTP or HTTPS on any host.
///
/// Use this only where another layer, such as an egress policy, decides
/// whether plain HTTP may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpOrHttps {}

impl SchemePolicy for Https {
    fn check(scheme: &str, _host: &Host<&str>) -> Result<(), HttpUrlError> {
        match scheme {
            "https" => Ok(()),
            "http" => Err(HttpUrlError::RequiresHttps),
            _ => Err(HttpUrlError::UnsupportedScheme),
        }
    }
}

impl SchemePolicy for HttpsOrLoopbackHttp {
    fn check(scheme: &str, host: &Host<&str>) -> Result<(), HttpUrlError> {
        match scheme {
            "https" => Ok(()),
            "http" if is_loopback_host(host) => Ok(()),
            "http" => Err(HttpUrlError::HttpRequiresLoopback),
            _ => Err(HttpUrlError::UnsupportedScheme),
        }
    }
}

impl SchemePolicy for HttpOrHttps {
    fn check(scheme: &str, _host: &Host<&str>) -> Result<(), HttpUrlError> {
        match scheme {
            "https" | "http" => Ok(()),
            _ => Err(HttpUrlError::UnsupportedScheme),
        }
    }
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::Https {}
    impl Sealed for super::HttpsOrLoopbackHttp {}
    impl Sealed for super::HttpOrHttps {}
}

/// A scheme, host, and optional port, without a path, query, fragment, or
/// credentials.
///
/// The canonical serialization, used by [`fmt::Display`] and [`Serialize`],
/// is the ASCII origin serialization: a lowercase host, no default port, and no
/// trailing slash, such as `https://firma.example:8443`. Parsing accepts any
/// equivalent spelling, such as `https://Firma.Example:443/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpOrigin<P: SchemePolicy> {
    url: Url,
    policy: PhantomData<P>,
}

impl<P: SchemePolicy> HttpOrigin<P> {
    /// Validates `url` as an origin under the scheme policy `P`.
    ///
    /// # Errors
    ///
    /// Returns [`HttpUrlError`] when `url` has no host, has credentials, a path
    /// other than `/`, a query, or a fragment, or when `P` rejects its scheme.
    pub fn new(url: Url) -> Result<Self, HttpUrlError> {
        validate::<P>(&url, PathRule::Root)?;
        Ok(Self {
            url,
            policy: PhantomData,
        })
    }

    /// Returns the origin as a URL whose path is `/`.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.url
    }
}

impl From<HttpOrigin<Https>> for HttpOrigin<HttpsOrLoopbackHttp> {
    fn from(origin: HttpOrigin<Https>) -> Self {
        Self {
            url: origin.url,
            policy: PhantomData,
        }
    }
}

impl<P: SchemePolicy> fmt::Display for HttpOrigin<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.url.origin().ascii_serialization())
    }
}

/// An absolute HTTP(S) URL with a host and any path, without a query,
/// fragment, or credentials.
///
/// The URL is kept exactly as written, so a value whose path identity matters,
/// such as an OIDC issuer or a redirect URI, round-trips unchanged. To derive
/// a URL beneath it, use [`HttpUrl::join_path`] rather than [`Url::join`]:
/// `Url::join` replaces the last path segment unless the path ends with `/`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpUrl<P: SchemePolicy> {
    url: Url,
    policy: PhantomData<P>,
}

impl<P: SchemePolicy> HttpUrl<P> {
    /// Validates `url` under the scheme policy `P`.
    ///
    /// # Errors
    ///
    /// Returns [`HttpUrlError`] when `url` has no host, has credentials, a
    /// query, or a fragment, or when `P` rejects its scheme.
    pub fn new(url: Url) -> Result<Self, HttpUrlError> {
        validate::<P>(&url, PathRule::Any)?;
        Ok(Self {
            url,
            policy: PhantomData,
        })
    }

    /// Returns the URL as written.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.url
    }

    /// Returns this URL with `relative` appended beneath its path, treating
    /// the path as a directory whether or not it ends with `/`.
    ///
    /// For example, `approvals/1` joined to `https://firma.example/team` is
    /// `https://firma.example/team/approvals/1`. `relative` is appended
    /// verbatim, so it should not start with `/`.
    #[must_use]
    pub fn join_path(&self, relative: &str) -> Url {
        let mut url = self.url.clone();
        let separator = if url.path().ends_with('/') { "" } else { "/" };
        let path = format!("{}{separator}{relative}", url.path());
        url.set_path(&path);
        url
    }
}

impl<P: SchemePolicy> fmt::Display for HttpUrl<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.url.as_str())
    }
}

macro_rules! string_conversions {
    ($type:ident) => {
        impl<P: SchemePolicy> FromStr for $type<P> {
            type Err = ParseHttpUrlError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Ok(Self::new(Url::parse(value)?)?)
            }
        }

        impl<P: SchemePolicy> Serialize for $type<P> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de, P: SchemePolicy> Deserialize<'de> for $type<P> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

string_conversions!(HttpOrigin);
string_conversions!(HttpUrl);

/// Why text does not parse as an [`HttpOrigin`] or [`HttpUrl`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseHttpUrlError {
    /// The text is not an absolute URL.
    #[error("URL is malformed: {0}")]
    Malformed(#[from] url::ParseError),

    /// The URL does not have the required shape or scheme.
    #[error(transparent)]
    Invalid(#[from] HttpUrlError),
}

/// Why a URL is not a valid [`HttpOrigin`] or [`HttpUrl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpUrlError {
    /// The URL does not identify a host.
    #[error("URL must include a host")]
    MissingHost,

    /// The URL includes a user name or password.
    #[error("URL must not include credentials")]
    Credentials,

    /// An origin includes a path other than `/`.
    #[error("origin must not include a path")]
    Path,

    /// The URL includes a query, even an empty one.
    #[error("URL must not include a query")]
    Query,

    /// The URL includes a fragment, even an empty one.
    #[error("URL must not include a fragment")]
    Fragment,

    /// The scheme is neither HTTP nor HTTPS.
    #[error("URL must use HTTP or HTTPS")]
    UnsupportedScheme,

    /// The URL uses HTTP where only HTTPS is allowed.
    #[error("URL must use HTTPS")]
    RequiresHttps,

    /// The URL uses HTTP with a host that is not loopback.
    #[error("URL must use HTTPS unless its host is loopback")]
    HttpRequiresLoopback,
}

#[derive(Clone, Copy)]
enum PathRule {
    Root,
    Any,
}

fn validate<P: SchemePolicy>(url: &Url, path: PathRule) -> Result<(), HttpUrlError> {
    let host = url.host().ok_or(HttpUrlError::MissingHost)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpUrlError::Credentials);
    }
    if matches!(path, PathRule::Root) && url.path() != "/" {
        return Err(HttpUrlError::Path);
    }
    if url.query().is_some() {
        return Err(HttpUrlError::Query);
    }
    if url.fragment().is_some() {
        return Err(HttpUrlError::Fragment);
    }
    P::check(url.scheme(), &host)
}

/// Returns whether `url`'s host is `localhost`, an IPv4 loopback address, or the
/// IPv6 loopback address, the hosts [`HttpsOrLoopbackHttp`] allows over HTTP.
#[must_use]
pub fn is_loopback(url: &Url) -> bool {
    url.host().is_some_and(|host| is_loopback_host(&host))
}

/// Returns whether a URI `host` names this machine.
///
/// That is `localhost` or a loopback address, including an IPv4 loopback
/// address written as IPv4-mapped IPv6; an IPv6 literal may be bracketed and a
/// name may carry a trailing dot.
///
/// This is where a server certificate would come from a local CA rather than
/// a public one. It is broader than [`is_loopback`], which decides where plain
/// HTTP is allowed and accepts neither an IPv4-mapped address nor a trailing
/// dot.
#[must_use]
pub fn host_is_this_machine(host: &str) -> bool {
    let unbracketed = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    unbracketed.eq_ignore_ascii_case("localhost")
        || unbracketed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}
