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
//! broker → {"type":"ok","stdout":"<base64>"}\n     (on success)
//! broker → {"type":"err","error":"<reason>"}\n     (on failure — shim exits non-zero)
//! ```
//!
//! Layout mirrors the secret gateway's: shared wire types live here,
//! [`client`] is the shim-side connector, and [`server`] is the broker-side
//! listener.
//!
//! Size caps: stdout is base64-encoded onto the wire, so a configured
//! response cap of `N` bytes admits roughly `3N/4` bytes of raw tool stdout.
//! The [`client`] and [`server`] defaults are aligned so both sides agree on
//! the largest request and response lines; tune them together.

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

/// Shim → broker request: describes one tool invocation, which the broker's
/// handler may refuse (config matching and authorization happen downstream in
/// the handler, not in the shim).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BrokerRequest<'a> {
    /// Executable basename of the wrapped tool (e.g. `"bws"`).
    #[serde(borrow)]
    pub bin: Str<'a>,
    /// Arguments (everything after the binary name).
    #[serde(borrow)]
    pub args: Vec<Str<'a>>,
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
    ///
    /// The whole payload is base64-encoded into memory here, so handlers must
    /// cap tool stdout capture: an unbounded payload would exhaust broker
    /// memory before the listener's response-size check (see
    /// [`server::config::BrokerListenerConfig::max_buffer_size`]) can
    /// reject it.
    #[must_use]
    pub fn ok(stdout: &[u8]) -> Self {
        Self::Ok {
            stdout: Str::from(base64::engine::general_purpose::STANDARD.encode(stdout)),
        }
    }

    /// Build an error response.
    #[must_use]
    pub fn err<'a>(reason: impl Into<Str<'a>>) -> BrokerResponse<'a> {
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
    pub fn into_stdout(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Ok { stdout } => base64::engine::general_purpose::STANDARD
                .decode(&*stdout)
                .map_err(|e| format!("broker response base64 decode failed: {e}")),
            Self::Err { error } => Err(error.to_string()),
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
    // `saturating_add` keeps a caller passing `max_bytes` at the type's
    // ceiling from overflowing the `+ 1` boundary byte.
    let mut buf = tokio::io::BufReader::new(stream.take(max_bytes.saturating_add(1)));
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
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    getsockopt(stream, PeerCredentials)
        .map(|creds| creds.uid())
        .map_err(io::Error::from)
}

/// [`peer_uid`] on BSD-family platforms, where the Linux `SO_PEERCRED` sockopt
/// is unavailable.
#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    match nix::unistd::getpeereid(stream) {
        Ok((user_id, _group_id)) => Ok(user_id.as_raw()),
        Err(err_no) => Err(io::Error::from(err_no)),
    }
}

/// The uid of the current process.
#[cfg(unix)]
fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}
