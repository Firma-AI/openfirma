//! Out-of-sandbox broker transport for the secret shim.
//!
//! The shim binary connects to the broker over a Unix domain socket (Unix) or
//! TCP loopback (Windows) and sends a newline-terminated JSON request. The
//! broker dispatches each request to its handler, which applies config
//! matching and authorization to decide whether the real CLI runs out of the
//! sandbox; when it does, the handler intercepts the output, and the broker
//! writes back a newline-terminated JSON response containing the base64-encoded
//! stdout.
//!
//! Protocol (one round-trip per connection):
//!
//! ```text
//! shim  →  {"bin":"bws","args":["secret","get","abc"]}\n
//! broker → {"type":"Ok","stdout":"<base64>"}\n     (on success)
//! broker → {"type":"Err","error":"<reason>"}\n     (on failure — shim exits non-zero)
//! ```
//!
//! Layout mirrors the secret gateway's: shared wire types live here,
//! [`client`] is the shim-side connector, and [`server`] is the broker-side
//! listener.

#![allow(
    dead_code,
    reason = "transport is wired by the secret shim in a later PR"
)]

pub mod client;
pub mod server;
pub mod stream;

use std::io;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;

use base64::Engine as _;
use firma_http::Str;
use serde::{Deserialize, Serialize};

use crate::config::CommandMediatorEndpoint;

/// Shim → broker request: describes one tool invocation, which the broker's
/// handler may refuse (config matching and authorization happen downstream in
/// the handler, not in the shim).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct BrokerRequest<'a, T: ArgsList> {
    /// Executable basename of the wrapped tool (e.g. `"bws"`).
    #[serde(borrow)]
    pub bin: Str<'a>,
    /// Arguments (everything after the binary name).
    pub args: T,
}

pub(crate) trait ArgsList: sealed::Sealed {}

impl<T> ArgsList for T where T: sealed::Sealed {}

mod sealed {
    use firma_http::Str;
    use serde::Serialize;

    pub trait Sealed: Serialize + Sync {}

    impl Sealed for Vec<String> {}

    impl Sealed for Vec<Str<'_>> {}

    impl Sealed for Vec<&'_ str> {}

    impl Sealed for &'_ [String] {}

    impl<'a> Sealed for &'a [Str<'a>] {}

    impl<'a> Sealed for &'a [&'a str] {}
}

/// Broker → shim response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum BrokerResponse<'a> {
    Ok {
        /// Base64-encoded stdout bytes from the real tool.
        #[serde(borrow)]
        stdout: Str<'a>,
    },
    Err {
        #[serde(borrow)]
        error: Str<'a>,
    },
}

impl BrokerResponse<'_> {
    /// Build a success response from raw stdout bytes.
    #[must_use]
    pub(crate) fn ok(stdout: &[u8]) -> Self {
        Self::Ok {
            stdout: Str::from(base64::engine::general_purpose::STANDARD.encode(stdout)),
        }
    }

    /// Build an error response.
    #[must_use]
    pub(crate) fn err<'a>(reason: impl Into<Str<'a>>) -> BrokerResponse<'a> {
        BrokerResponse::Err {
            error: reason.into(),
        }
    }

    /// Decode the stdout bytes from a success response.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is an error response or the base64 is
    /// malformed.
    pub(crate) fn into_stdout(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Ok { stdout } => base64::engine::general_purpose::STANDARD
                .decode(&*stdout)
                .map_err(|e| format!("broker response base64 decode failed: {e}")),
            Self::Err { error } => Err(error.to_string()),
        }
    }
}

/// Address-level endpoint invariants shared by both transport roles.
///
/// The broker returns secret material, so the transport must stay local: on
/// Unix hosts only a Unix socket can carry the same-user guarantee that peer
/// credentials provide, and on any platform a non-loopback TCP endpoint would
/// expose the broker to remote callers. A relative Unix path is an ambiguous
/// config bug that must fail closed.
pub(crate) fn validate_endpoint(endpoint: &CommandMediatorEndpoint) -> Result<(), String> {
    match endpoint {
        #[cfg(unix)]
        CommandMediatorEndpoint::Tcp { .. } => Err(
            "secret broker tcp endpoint is only supported on Windows; use unix:// on unix hosts"
                .to_string(),
        ),
        #[cfg(not(unix))]
        CommandMediatorEndpoint::Tcp { addr } => {
            if !addr.ip().is_loopback() {
                return Err(format!(
                    "secret broker endpoint must be a loopback address, got {addr}"
                ));
            }
            Ok(())
        }
        CommandMediatorEndpoint::Unix { path } => {
            if !path.is_absolute() {
                return Err(format!(
                    "secret broker unix endpoint must be an absolute path: {}",
                    path.display()
                ));
            }
            Ok(())
        }
    }
}

/// Read one newline-terminated line from `stream` with `max_bytes` as the
/// line-size limit.
///
/// The underlying read is capped at `max_bytes + 1` so a line without a
/// trailing newline cannot grow without bound; the `+ 1` lets an over-limit
/// line still trip the caller's size check instead of being silently truncated
/// to exactly the limit. The caller bounds the whole exchange with
/// [`tokio::time::timeout`], so a peer that trickles bytes cannot hold the
/// connection indefinitely.
pub(crate) async fn read_bounded_line<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_bytes: u64,
) -> io::Result<Vec<u8>> {
    let mut buf = tokio::io::BufReader::new(stream.take(max_bytes + 1));
    let mut line = Vec::new();
    buf.read_until(b'\n', &mut line).await?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    Ok(line)
}

/// Write all of `payload` to `stream` and flush.
///
/// The caller bounds the whole exchange with [`tokio::time::timeout`], so a
/// peer that stops reading cannot hold the connection indefinitely.
pub(crate) async fn write_all<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> io::Result<()> {
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Read and discard everything remaining on `stream` until EOF.
///
/// Used after writing an error response for an over-limit request whose bytes
/// are still in flight: closing a TCP socket that still has unread data in its
/// receive buffer makes the OS send RST instead of FIN, which can discard the
/// response the client has not read yet. Draining first keeps the close
/// graceful. The caller bounds the exchange with [`tokio::time::timeout`], so a
/// peer that streams indefinitely cannot hold the connection past the deadline.
pub(crate) async fn drain_remaining<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
}

/// The real uid of the process that owns the Unix socket on the other side of
/// `stream`.
///
/// Linux exposes it via the `SO_PEERCRED` sockopt; BSD-family platforms (where
/// the sockopt is unavailable) use `getpeereid`.
#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    getsockopt(stream, PeerCredentials)
        .map(|creds| creds.uid())
        .map_err(io::Error::from)
}

/// [`peer_uid`] on BSD-family platforms, where the Linux `SO_PEERCRED` sockopt
/// is unavailable.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;

    let (mut effective_user_id, mut effective_group_id) = (0u32, 0u32);
    // SAFETY: euid/egid are initialized by the kernel on success.
    #[expect(unsafe_code, reason = "BSD getpeereid bindings are unsafe")]
    if unsafe {
        libc::getpeereid(
            stream.as_raw_fd(),
            &raw mut effective_user_id,
            &raw mut effective_group_id,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(effective_user_id)
}

/// The uid of the current process.
#[cfg(unix)]
pub(crate) fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}
