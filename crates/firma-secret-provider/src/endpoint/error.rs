use std::{
    io,
    net::{AddrParseError, IpAddr},
};

/// Errors returned by [`super::EndpointInner::parse_client`] and [`super::EndpointInner::parse_server`]
/// when an address string is malformed or names a scheme unavailable on the current platform.
#[derive(Debug, thiserror::Error)]
pub enum EndpointParseError {
    /// The `tcp://` prefix matched, but the remainder did not parse as a
    /// `SocketAddr`.
    #[error("invalid TCP address '{addr}': {error}")]
    InvalidTCP {
        addr: String,
        #[source]
        error: AddrParseError,
    },
    #[error("IO error: {0}")]
    IO(#[source] io::Error),
    /// A `unix://` address was given on a non-unix system.
    #[error("unix address '{0}' is not supported on this platform")]
    UnixUnsupported(String),
    /// The string had neither a `tcp://` nor a `unix://` prefix.
    #[error("unrecognized address '{0}'; expected 'tcp://host:port' or 'unix:///path'")]
    Unrecognized(String),
    #[error("TCP gateway address {0} is not a loopback address")]
    NoLoopback(IpAddr),
    #[error("not absolute socket file {0}")]
    NotAbsolute(String),
    #[error("no parent for socket file {0}")]
    NoParent(String),
    #[error("wrong permissions for socket file {0}")]
    WrongPermissions(String),
}
