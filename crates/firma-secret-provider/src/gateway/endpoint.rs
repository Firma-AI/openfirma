use std::{
    fmt::Display,
    io,
    net::{AddrParseError, IpAddr, SocketAddr},
};

/// Errors returned by [`GatewayEndpoint::parse`] when a
/// [`crate::gateway::client::GATEWAY_ADDR_ENV`]-style address string is
/// malformed or names a scheme unavailable on the current platform.
#[derive(Debug, thiserror::Error)]
pub enum GatewayEndpointParseError {
    /// The `tcp:` prefix matched, but the remainder did not parse as a
    /// `SocketAddr`.
    #[error("invalid TCP gateway address '{addr}': {error}")]
    InvalidTCP {
        addr: String,
        #[source]
        error: AddrParseError,
    },
    #[error("IO error: {0}")]
    IO(#[source] io::Error),
    /// A `unix:` address was given on a non-unix system.
    #[error("unix gateway address '{0}' is not supported on this platform")]
    UnixUnsupported(String),
    /// The string had neither a `tcp:` nor a `unix:` prefix.
    #[error("unrecognized gateway address '{0}'; expected 'tcp:<host>:<port>' or 'unix:<path>'")]
    Unrecognized(String),
    #[error("TCP gateway address {0} is not a loopback address")]
    NoLoopback(IpAddr),
    #[error("no parent for gateway socket file {0}")]
    NoParent(String),
    #[error("wrong permissions for gateway socket file {0}")]
    WrongPermissions(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayEndpoint(GatewayEndpointInner);

/// Transport address for the firma-run secret resolution gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEndpointInner {
    /// TCP loopback socket (Windows, and any platform when configured).
    Tcp(SocketAddr),
    /// Unix domain socket (Linux/macOS).
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl GatewayEndpoint {
    /// Parse a `unix:<path>` or `tcp:<host>:<port>` address string.
    ///
    /// # Errors
    ///
    /// Returns an error [`GatewayEndpointParseError`] if the scheme is unrecognized, the TCP address
    /// is malformed, or a `unix:` address is used on a non-Unix platform.
    pub fn parse(s: &str) -> Result<Self, GatewayEndpointParseError> {
        if let Some(addr_str) = s.strip_prefix("tcp:") {
            let addr = addr_str.parse::<SocketAddr>().map_err(|error| {
                GatewayEndpointParseError::InvalidTCP {
                    addr: addr_str.to_owned(),
                    error,
                }
            })?;
            let ip = addr.ip();
            if !ip.is_loopback() {
                return Err(GatewayEndpointParseError::NoLoopback(ip));
            }
            return Ok(Self(GatewayEndpointInner::Tcp(addr)));
        }

        if let Some(path_str) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{FileTypeExt, PermissionsExt};

                let is_exact =
                    |path: &std::path::Path,
                     mode: u32,
                     is_expected_type: fn(&std::fs::FileType) -> bool| {
                        let metadata = path
                            .symlink_metadata()
                            .map_err(GatewayEndpointParseError::IO)?;
                        Ok::<_, GatewayEndpointParseError>(
                            is_expected_type(&metadata.file_type())
                                && metadata.permissions().mode() & 0o777 == mode,
                        )
                    };

                let socket_file = std::path::PathBuf::from(path_str);
                let parent = socket_file
                    .parent()
                    .ok_or_else(|| GatewayEndpointParseError::NoParent(path_str.to_owned()))?;
                let socket_ok = is_exact(&socket_file, 0o600, std::fs::FileType::is_socket)?;
                let parent_ok = is_exact(parent, 0o700, std::fs::FileType::is_dir)?;
                if !socket_ok || !parent_ok {
                    return Err(GatewayEndpointParseError::WrongPermissions(
                        path_str.to_owned(),
                    ));
                }
                return Ok(Self(GatewayEndpointInner::Unix(socket_file)));
            }

            #[cfg(not(unix))]
            {
                let _ = path_str;
                return Err(GatewayEndpointParseError::UnixUnsupported(s.to_owned()));
            }
        }

        Err(GatewayEndpointParseError::Unrecognized(s.to_owned()))
    }

    #[must_use]
    pub fn as_inner(&self) -> &GatewayEndpointInner {
        &self.0
    }
}

impl Display for GatewayEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            GatewayEndpointInner::Tcp(addr) => write!(f, "tcp:{addr}"),
            #[cfg(unix)]
            GatewayEndpointInner::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}
