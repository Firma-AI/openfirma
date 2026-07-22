//! Out-of-sandbox broker transport for the secret shim.
//!
//! The shim binary connects to the broker over a Unix domain socket and sends a
//! newline-terminated JSON request describing the tool launch. The broker runs
//! the real CLI out of the sandbox, intercepts the output, and writes back a
//! newline-terminated JSON response containing the base64-encoded stdout.
//!
//! Protocol (one round-trip per connection):
//!
//! ```text
//! shim  →  {"bin":"bws","args":"secret get abc"}\n
//! broker → {"stdout":"<base64>"}\n        (on success)
//! broker → {"error":"<reason>"}\n         (on failure — shim exits non-zero)
//! ```

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Maximum request line length from the shim, in bytes.
const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Shim → broker request: describes one tool launch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BrokerRequest {
    /// Executable basename of the wrapped tool (e.g. `"bws"`).
    pub bin: String,
    /// Space-joined arguments (everything after the binary name).
    pub args: String,
}

/// Broker → shim response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BrokerResponse {
    Ok {
        /// Base64-encoded stdout bytes from the real tool.
        stdout: String,
    },
    Err {
        error: String,
    },
}

impl BrokerResponse {
    /// Build a success response from raw stdout bytes.
    #[must_use]
    pub fn ok(stdout: &[u8]) -> Self {
        Self::Ok {
            stdout: base64::engine::general_purpose::STANDARD.encode(stdout),
        }
    }

    /// Build an error response.
    #[must_use]
    pub fn err(reason: impl Into<String>) -> Self {
        Self::Err {
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
                .decode(stdout)
                .map_err(|e| format!("broker response base64 decode failed: {e}")),
            Self::Err { error } => Err(error),
        }
    }
}

/// Broker-side listener: accepts shim connections and dispatches requests.
#[derive(Debug)]
pub struct BrokerListener {
    listener: UnixListener,
    path: PathBuf,
}

impl BrokerListener {
    /// Bind a listener at `path`, removing any stale socket file first.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if removing a stale socket (other than
    /// a missing one) or binding fails.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Err(error) = std::fs::remove_file(&path)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(error);
        }
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }

    /// The bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept one shim connection, invoke `handler(request)`, and write the
    /// response back.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if accepting, reading, or writing fails. Handler
    /// errors are serialized and written as `{"error":"..."}` responses rather
    /// than returned here.
    pub fn accept_one<F>(&self, handler: F) -> io::Result<()>
    where
        F: FnOnce(BrokerRequest) -> BrokerResponse,
    {
        let (mut stream, _addr) = self.listener.accept()?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.len() > MAX_REQUEST_BYTES {
            let response = BrokerResponse::err("request too large");
            return write_response(&mut stream, &response);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(io::Error::other("empty broker request"));
        }
        let response = match serde_json::from_str::<BrokerRequest>(trimmed) {
            Ok(request) => handler(request),
            Err(e) => BrokerResponse::err(format!("malformed broker request: {e}")),
        };
        write_response(&mut stream, &response)
    }
}

impl Drop for BrokerListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn write_response(stream: &mut impl Write, response: &BrokerResponse) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("failed to serialize broker response: {e}")))?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    use super::*;

    fn connect_and_send(path: &Path, request: &BrokerRequest) -> BrokerResponse {
        let mut stream = UnixStream::connect(path).expect("connect");
        let payload = serde_json::to_string(request).expect("serialize");
        stream
            .write_all(format!("{payload}\n").as_bytes())
            .expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        serde_json::from_str(line.trim()).expect("deserialize response")
    }

    #[test]
    fn roundtrip_ok_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let listener = BrokerListener::bind(&path).expect("bind");

        let request = BrokerRequest {
            bin: "bws".to_string(),
            args: "secret get abc".to_string(),
        };
        let request_clone = request.clone();

        let server = thread::spawn(move || {
            listener
                .accept_one(|req| {
                    assert_eq!(req, request_clone);
                    BrokerResponse::ok(b"secret-value")
                })
                .expect("accept_one");
        });

        let response = connect_and_send(&path, &request);
        server.join().expect("server thread");

        let stdout = response.into_stdout().expect("ok response");
        assert_eq!(stdout, b"secret-value");
    }

    #[test]
    fn handler_error_written_as_error_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker-err.sock");
        let listener = BrokerListener::bind(&path).expect("bind");

        let request = BrokerRequest {
            bin: "bws".to_string(),
            args: "secret get x".to_string(),
        };

        let server = thread::spawn(move || {
            listener
                .accept_one(|_req| BrokerResponse::err("tool not found"))
                .expect("accept_one");
        });

        let response = connect_and_send(&path, &request);
        server.join().expect("server thread");
        assert!(response.into_stdout().is_err());
    }

    #[test]
    fn listener_cleans_up_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cleanup.sock");
        {
            let _listener = BrokerListener::bind(&path).expect("bind");
            assert!(path.exists());
        }
        assert!(!path.exists());
    }
}
