use std::{fmt::Display, net::SocketAddr};

pub mod client;
pub mod error;
pub mod server;

/// Transport address for the secret resolution gateway and the shim broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointInner {
    /// TCP loopback socket (Windows, and any platform when configured).
    Tcp(SocketAddr),
    /// Unix domain socket (Linux/macOS).
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

impl EndpointInner {
    /// Parse a `unix:///path` or `tcp://host:port` address string.
    ///
    /// Client-side parsing is strict about the transport's security
    /// invariants, so it must run when the peer socket already exists:
    ///
    /// - TCP addresses must be loopback. Note that over TCP the peer-uid
    ///   checks the Unix transport performs at connect time do not apply —
    ///   a `tcp://` endpoint on a Unix host therefore relies on loopback
    ///   binding alone to keep cross-user traffic out.
    /// - Unix socket files must be absolute, already exist, be a real socket
    ///   (not a symlink or regular file), and be `0600`; their immediate
    ///   parent directory must be `0700`. A socket whose parent was created
    ///   with default permissions (e.g. `0755`) is rejected, so the binding
    ///   side must create the parent `0700`.
    ///
    /// # Errors
    ///
    /// Returns an error [`EndpointParseError`] if the scheme is unrecognized, the TCP address
    /// is malformed, a `unix://` address is used on a non-Unix platform, or the
    /// Unix socket fails the existence, type, or permission checks above.
    fn parse_client(s: &str) -> Result<Self, error::EndpointParseError> {
        if let Some(addr_str) = s.strip_prefix("tcp://") {
            let addr = addr_str.parse::<SocketAddr>().map_err(|error| {
                error::EndpointParseError::InvalidTCP {
                    addr: addr_str.to_owned(),
                    error,
                }
            })?;
            let ip = addr.ip();
            if !ip.is_loopback() {
                return Err(error::EndpointParseError::NoLoopback(ip));
            }
            return Ok(Self::Tcp(addr));
        }

        if let Some(path_str) = s.strip_prefix("unix://") {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{FileTypeExt, PermissionsExt};

                let is_exact =
                    |path: &std::path::Path,
                     mode: u32,
                     is_expected_type: fn(&std::fs::FileType) -> bool| {
                        let metadata = path
                            .symlink_metadata()
                            .map_err(error::EndpointParseError::IO)?;
                        Ok::<_, error::EndpointParseError>(
                            is_expected_type(&metadata.file_type())
                                && metadata.permissions().mode() & 0o777 == mode,
                        )
                    };

                let socket_file = std::path::PathBuf::from(path_str);
                if !socket_file.is_absolute() {
                    return Err(error::EndpointParseError::NotAbsolute(path_str.to_owned()));
                }
                let parent = socket_file
                    .parent()
                    .ok_or_else(|| error::EndpointParseError::NoParent(path_str.to_owned()))?;
                let socket_ok = is_exact(&socket_file, 0o600, std::fs::FileType::is_socket)?;
                let parent_ok = is_exact(parent, 0o700, std::fs::FileType::is_dir)?;
                if !socket_ok || !parent_ok {
                    return Err(error::EndpointParseError::WrongPermissions(
                        path_str.to_owned(),
                    ));
                }
                return Ok(Self::Unix(socket_file));
            }

            #[cfg(not(unix))]
            {
                let _ = path_str;
                return Err(error::EndpointParseError::UnixUnsupported(s.to_owned()));
            }
        }

        Err(error::EndpointParseError::Unrecognized(s.to_owned()))
    }

    /// Parse a `unix:///path` or `tcp://host:port` address string.
    ///
    /// # Errors
    ///
    /// Returns an error [`EndpointParseError`] if the scheme is unrecognized, the TCP address
    /// is malformed, or a `unix://` address is used on a non-Unix platform.
    fn parse_server(s: &str) -> Result<Self, error::EndpointParseError> {
        if let Some(addr_str) = s.strip_prefix("tcp://") {
            let addr = addr_str.parse::<SocketAddr>().map_err(|error| {
                error::EndpointParseError::InvalidTCP {
                    addr: addr_str.to_owned(),
                    error,
                }
            })?;
            let ip = addr.ip();
            if !ip.is_loopback() {
                return Err(error::EndpointParseError::NoLoopback(ip));
            }
            return Ok(Self::Tcp(addr));
        }

        if let Some(path_str) = s.strip_prefix("unix://") {
            #[cfg(unix)]
            {
                let socket_file = std::path::PathBuf::from(path_str);
                if !socket_file.is_absolute() {
                    return Err(error::EndpointParseError::NotAbsolute(path_str.to_owned()));
                }
                // TODO: do we need other checks for server-side?
                return Ok(Self::Unix(socket_file));
            }

            #[cfg(not(unix))]
            {
                let _ = path_str;
                return Err(error::EndpointParseError::UnixUnsupported(s.to_owned()));
            }
        }

        Err(error::EndpointParseError::Unrecognized(s.to_owned()))
    }
}

impl Display for EndpointInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}
