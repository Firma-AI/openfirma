//! Out-of-sandbox broker transport for the secret shim.
//!
//! The shim binary connects to the broker over a Unix domain socket (Unix) or
//! TCP loopback (Windows) and sends a newline-terminated JSON request. The
//! broker runs the real CLI out of the sandbox, intercepts the output, and
//! writes back a newline-terminated JSON response containing the base64-encoded
//! stdout.
//!
//! Protocol (one round-trip per connection):
//!
//! ```text
//! shim  →  {"bin":"bws","args":"secret get abc"}\n
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

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use base64::Engine as _;
use firma_http::Str;
use serde::{Deserialize, Serialize};

use crate::config::CommandMediatorEndpoint;

/// Shim → broker request: describes one tool launch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BrokerRequest<'a> {
    /// Executable basename of the wrapped tool (e.g. `"bws"`).
    #[serde(borrow)]
    pub bin: Str<'a>,
    /// Space-joined arguments (everything after the binary name).
    #[serde(borrow)]
    pub args: Str<'a>,
}

/// Broker → shim response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrokerResponse<'a> {
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

/// A connected broker socket, abstracting over the TCP and Unix transports.
///
/// Shared by the shim-side [`client::BrokerClient`] (outbound connections)
/// and the broker-side [`server::BrokerListener`] (accepted connections).
#[derive(Debug)]
pub(crate) enum BrokerStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl BrokerStream {
    /// Set the read deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot apply the timeout.
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }

    /// Set the write deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot apply the timeout.
    pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_write_timeout(timeout),
        }
    }
}

impl io::Read for BrokerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl io::Write for BrokerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
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

/// Read one newline-terminated line from `stream`, bounded by both a byte cap
/// and an absolute wall-clock deadline.
///
/// `max_bytes` is the maximum number of bytes read, exclusive of any trailing
/// newline (the newline is truncated from the result). Reading stops at the
/// first newline, at EOF, or once `max_bytes` bytes have been collected. The
/// per-read timeout is re-armed to the remaining budget before every read, so
/// a peer that trickles bytes cannot hold the connection past `deadline`.
pub(crate) fn read_line_bounded(
    stream: &mut BrokerStream,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let cap = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut line = Vec::with_capacity(usize::min(cap, 256));
    let mut buf = [0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker read deadline exceeded",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(line);
        }
        let remaining_cap = cap.saturating_sub(line.len());
        if let Some(pos) = buf[..n].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..usize::min(pos, remaining_cap)]);
            return Ok(line);
        }
        line.extend_from_slice(&buf[..usize::min(n, remaining_cap)]);
        if line.len() >= cap {
            return Ok(line);
        }
    }
}

/// Write all of `payload` to `stream` before `deadline`.
///
/// The per-write timeout is re-armed to the remaining budget before every
/// write, so a peer that stops reading cannot hold the connection past
/// `deadline`.
pub(crate) fn write_all_bounded(
    stream: &mut BrokerStream,
    mut payload: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !payload.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker write deadline exceeded",
            ));
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(payload) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write broker payload",
                ));
            }
            Ok(n) => payload = &payload[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "broker write deadline exceeded",
                ));
            }
            Err(e) => return Err(e),
        }
    }
    stream.flush()
}

/// Read one newline-terminated line from `stream` with `max_bytes` as the
/// line-size limit, under an absolute wall-clock deadline.
///
/// The underlying read is capped at `max_bytes + 1` so a line without a
/// trailing newline cannot grow without bound; the `+ 1` lets an over-limit
/// line still trip the caller's size check instead of being silently truncated
/// to exactly the limit.
pub(crate) fn read_bounded_line(
    stream: &mut BrokerStream,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    read_line_bounded(stream, max_bytes + 1, deadline)
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
