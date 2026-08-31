//! Out-of-sandbox broker transport for the secret shim.
//!
//! The shim binary connects to the broker over a Unix domain socket (Unix) or
//! TCP loopback (Windows) and sends a newline-terminated JSON request. The
//! broker dispatches each request to its handler, which applies config
//! matching and authorization to decide whether the real CLI runs out of the
//! sandbox; when it does, the handler intercepts the output, and the broker
//! writes back a newline-terminated JSON response containing base64-encoded,
//! stream-tagged output chunks in observed capture order.
//!
//! Protocol (one round-trip per connection):
//!
//! ```text
//! shim  →  {"bin":"bws","args":["secret","get","abc"]}\n
//! broker → {"type":"executed","output":[{"stream":"stdout","data":"<base64>"}],"status":{"type":"exited","code":0}}\n
//! broker → {"type":"rejected","error":"<reason>"}\n
//! ```
//!
//! Layout mirrors the secret gateway's: shared wire types live here,
//! [`client`] is the shim-side connector, and [`server`] is the broker-side
//! listener.
//!
//! Size caps: process output is base64-encoded onto the wire, so a configured
//! response cap of `N` bytes admits at most roughly `3N/4` bytes of total raw
//! output. JSON framing and per-chunk stream metadata reduce the usable payload,
//! especially when output is split into many small chunks. The [`client`] and
//! [`server`] defaults are aligned so both sides agree on the largest request
//! and response lines; tune them together.

pub mod client;
pub mod server;
pub mod stream;

use std::{fmt::Display, io, ops::Deref};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;

use base64::Engine as _;
use firma_http::Str;
use serde::{Deserialize, Serialize};

/// A validated executable basename from a shim request.
///
/// The broker resolves executable names outside the sandbox, so wire input
/// must remain one path component on both Unix and Windows. In particular,
/// absolute paths, parent traversal, and platform-specific separators are
/// rejected before a request reaches the handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct BinaryName<'a>(Str<'a>);

impl<'a> BinaryName<'a> {
    /// Validate `value` as a portable executable basename.
    ///
    /// # Errors
    ///
    /// Returns [`BinaryNameError`] when `value` is empty, is `.` or `..`, or
    /// contains a Unix or Windows path separator, drive separator, or NUL.
    pub fn new(value: impl Into<Str<'a>>) -> Result<Self, BinaryNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(BinaryNameError::Empty);
        }
        if &*value == "."
            || &*value == ".."
            || value
                .chars()
                .any(|character| matches!(character, '/' | '\\' | ':' | '\0'))
        {
            return Err(BinaryNameError::NotBasename(value.to_string()));
        }
        Ok(Self(value))
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for BinaryName<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(Str::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Deref for BinaryName<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for BinaryName<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Validation failures for [`BinaryName`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BinaryNameError {
    /// An executable basename cannot be empty.
    #[error("binary name must not be empty")]
    Empty,
    /// The value is not exactly one portable path component.
    #[error("binary name must be a single path component: {0}")]
    NotBasename(String),
}

/// Shim → broker request: describes one tool invocation, which the broker's
/// handler may refuse (config matching and authorization happen downstream in
/// the handler, not in the shim).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BrokerRequest<'a> {
    /// Executable basename of the wrapped tool (e.g. `"bws"`).
    #[serde(borrow)]
    pub bin: BinaryName<'a>,
    /// Arguments (everything after the binary name).
    #[serde(borrow)]
    pub args: Vec<Str<'a>>,
}

/// One base64-encoded, stream-tagged output chunk in a broker response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "stream", rename_all = "snake_case")]
pub enum BrokerResponseChunk<'a> {
    /// Bytes observed on stdout.
    Stdout {
        /// Base64-encoded chunk bytes.
        #[serde(borrow)]
        data: Str<'a>,
    },
    /// Bytes observed on stderr.
    Stderr {
        /// Base64-encoded chunk bytes.
        #[serde(borrow)]
        data: Str<'a>,
    },
}

/// Broker → shim response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrokerResponse<'a> {
    /// The real tool ran. Its complete observable process result follows.
    Executed {
        /// Base64-encoded output chunks in observed capture order.
        #[serde(borrow)]
        output: Vec<BrokerResponseChunk<'a>>,
        /// How the real tool terminated.
        status: BrokerExitStatus,
    },
    /// The broker refused or failed to launch the real tool.
    Rejected {
        #[serde(borrow)]
        error: Str<'a>,
    },
}

impl BrokerResponse<'_> {
    /// Build an execution response from stream-tagged output chunks and status.
    ///
    /// Chunks preserve the order in which concurrent stdout and stderr readers
    /// observed bytes. This is not a guarantee of the child process's exact
    /// cross-stream write order. Chunks are base64-encoded into memory here, so
    /// handlers must cap process output capture: an unbounded payload would
    /// exhaust broker memory before the listener's response-size check (see
    /// [`server::config::BrokerListenerConfig::max_response_size`]) can
    /// reject it.
    #[must_use]
    pub fn executed(
        output: impl IntoIterator<Item = BrokerOutputChunk>,
        status: BrokerExitStatus,
    ) -> Self {
        Self::Executed {
            output: output
                .into_iter()
                .map(|chunk| match chunk {
                    BrokerOutputChunk::Stdout(bytes) => BrokerResponseChunk::Stdout {
                        data: Str::from(base64::engine::general_purpose::STANDARD.encode(bytes)),
                    },
                    BrokerOutputChunk::Stderr(bytes) => BrokerResponseChunk::Stderr {
                        data: Str::from(base64::engine::general_purpose::STANDARD.encode(bytes)),
                    },
                })
                .collect(),
            status,
        }
    }

    /// Build a rejection response.
    #[must_use]
    pub fn rejected<'a>(reason: impl Into<Str<'a>>) -> BrokerResponse<'a> {
        BrokerResponse::Rejected {
            error: reason.into(),
        }
    }

    /// Decode an execution response's output chunks.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerResponseDecodeError`] if an output chunk is not valid
    /// base64.
    pub fn decode(self) -> Result<DecodedBrokerResponse, BrokerResponseDecodeError> {
        match self {
            Self::Executed { output, status } => {
                let output = output
                    .into_iter()
                    .enumerate()
                    .map(|(index, chunk)| match chunk {
                        BrokerResponseChunk::Stdout { data } => {
                            base64::engine::general_purpose::STANDARD
                                .decode(&*data)
                                .map(BrokerOutputChunk::Stdout)
                                .map_err(|source| BrokerResponseDecodeError::Stdout {
                                    index,
                                    source,
                                })
                        }
                        BrokerResponseChunk::Stderr { data } => {
                            base64::engine::general_purpose::STANDARD
                                .decode(&*data)
                                .map(BrokerOutputChunk::Stderr)
                                .map_err(|source| BrokerResponseDecodeError::Stderr {
                                    index,
                                    source,
                                })
                        }
                    })
                    .collect::<Result<_, _>>()?;
                Ok(DecodedBrokerResponse::Executed(BrokerOutput {
                    output,
                    status,
                }))
            }
            Self::Rejected { error } => Ok(DecodedBrokerResponse::Rejected(error.to_string())),
        }
    }
}

/// A platform-neutral process termination status returned by the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrokerExitStatus {
    /// The process exited normally with `code`.
    Exited { code: i32 },
    /// The process was terminated by a Unix signal.
    Signaled { signal: i32 },
    /// The platform reported neither an exit code nor a Unix signal.
    Unknown,
}

impl From<std::process::ExitStatus> for BrokerExitStatus {
    fn from(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self::Exited { code };
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;

            if let Some(signal) = status.signal() {
                return Self::Signaled { signal };
            }
        }
        Self::Unknown
    }
}

/// Raw output and termination status from a broker-executed tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerOutput {
    /// Stream-tagged bytes in observed capture order.
    pub output: Vec<BrokerOutputChunk>,
    /// How the real tool terminated.
    pub status: BrokerExitStatus,
}

/// One stream-tagged chunk of raw process output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerOutputChunk {
    /// Bytes observed on stdout.
    Stdout(Vec<u8>),
    /// Bytes observed on stderr.
    Stderr(Vec<u8>),
}

/// A decoded broker response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedBrokerResponse {
    /// The real tool ran and produced this observable result.
    Executed(BrokerOutput),
    /// The broker refused or failed to launch the real tool.
    Rejected(String),
}

/// Invalid base64 in a broker execution response.
#[derive(Debug, thiserror::Error)]
pub enum BrokerResponseDecodeError {
    /// A stdout chunk is not valid base64.
    #[error("broker returned invalid base64 stdout chunk {index}: {source}")]
    Stdout {
        /// Zero-based position in the observed output sequence.
        index: usize,
        #[source]
        source: base64::DecodeError,
    },
    /// A stderr chunk is not valid base64.
    #[error("broker returned invalid base64 stderr chunk {index}: {source}")]
    Stderr {
        /// Zero-based position in the observed output sequence.
        index: usize,
        #[source]
        source: base64::DecodeError,
    },
}

/// A bounded line read, including whether its framing delimiter arrived.
pub(crate) struct BoundedLine {
    /// The retained prefix of bytes before the delimiter or EOF.
    pub(crate) bytes: Vec<u8>,
    /// Whether the required newline delimiter arrived within the size limit.
    pub(crate) terminated: bool,
}

/// Read one line from `stream` with `max_bytes` as the line-size limit.
///
/// Retained bytes are capped at `max_bytes + 1` so a line cannot consume
/// unbounded memory; the `+ 1` lets an over-limit line still trip the caller's
/// size check instead of being silently truncated to exactly the limit. Once
/// the line exceeds the limit, the delimiter is irrelevant and the read
/// returns immediately. The caller bounds the whole exchange with
/// [`tokio::time::timeout`], so a peer that trickles bytes cannot hold the
/// connection indefinitely.
pub(crate) async fn read_bounded_line<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_bytes: u64,
) -> io::Result<BoundedLine> {
    // `saturating_add` keeps a caller passing `max_bytes` at the type's
    // ceiling from overflowing the `+ 1` boundary byte.
    let mut buf = tokio::io::BufReader::new(stream.take(max_bytes.saturating_add(1)));
    let mut line = Vec::new();
    buf.read_until(b'\n', &mut line).await?;
    let terminated = line.last() == Some(&b'\n');
    if terminated {
        line.pop();
    }
    Ok(BoundedLine {
        bytes: line,
        terminated,
    })
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

/// The effective uid of the process on the other side of `stream`.
///
/// Tokio selects the platform credential API: `SO_PEERCRED`, `getpeereid`, or
/// `getpeerucred`, depending on the Unix target.
#[cfg(unix)]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    stream.peer_cred().map(|credentials| credentials.uid())
}

/// The uid of the current process.
#[cfg(unix)]
fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}
