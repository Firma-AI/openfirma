//! Sidecar → firma-run secret resolution gateway.
//!
//! Serves a TCP loopback or Unix domain socket where the Sidecar sends
//! `secret.resolve` requests to look up placeholder tokens by name.
//! firma-run is the single source of truth for secrets; the Sidecar fetches on
//! demand, building per-request rehydration/masking state rather than caching
//! secrets persistently.
//!
//! # Protocol (newline-framed JSON)
//!
//! ```text
//! → {"placeholder":"firma-secret://bw/token","domain":"api.github.com"}
//! ← {"secret_b64":"...base64 bytes..."}   (success)
//! ← {"error":"unknown placeholder: ..."}  (failure)
//! ```
//!
//! The gateway transport is platform-dependent: a Unix domain socket on Unix
//! targets and a TCP loopback socket on Windows. Consumers discover the bound
//! address via the `FIRMA_SECRET_GATEWAY_ADDR` environment variable set by the
//! orchestrator.

use std::io::{self, BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::net::UnixListener;

use arc_swap::ArcSwap;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::config::CommandMediatorEndpoint;

use super::SecretStore;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
struct ResolveRequest {
    placeholder: String,
    /// Target host of the outbound request; forwarded for future domain-based
    /// access control. Currently used only for debug logging.
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ResolveResponse {
    Ok { secret_b64: String },
    Err { error: String },
}

enum GatewayInner {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener, PathBuf),
}

/// Secret gateway listener for the Sidecar MITM pipeline.
///
/// Accepts `secret.resolve` requests over a Unix domain socket (Unix) or TCP
/// loopback (Windows). The transport is selected at bind time via
/// [`CommandMediatorEndpoint`].
pub struct SecretGatewayListener {
    inner: GatewayInner,
}

impl SecretGatewayListener {
    /// Bind the gateway to `endpoint`.
    ///
    /// For Unix endpoints, any stale socket file is removed before binding.
    /// For TCP endpoints with port `0`, the OS assigns a free port; retrieve
    /// it with [`bound_endpoint`][Self::bound_endpoint].
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub fn bind(endpoint: &CommandMediatorEndpoint) -> io::Result<Self> {
        match endpoint {
            CommandMediatorEndpoint::Tcp { addr } => {
                let listener = TcpListener::bind(addr)?;
                Ok(Self {
                    inner: GatewayInner::Tcp(listener),
                })
            }
            #[cfg(unix)]
            CommandMediatorEndpoint::Unix { path } => {
                match std::fs::remove_file(path) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
                let listener = UnixListener::bind(path)?;
                Ok(Self {
                    inner: GatewayInner::Unix(listener, path.clone()),
                })
            }
            #[cfg(not(unix))]
            CommandMediatorEndpoint::Unix { .. } => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix domain sockets are not supported on this platform",
            )),
        }
    }

    /// Return the address this listener is actually bound to.
    ///
    /// For TCP with port `0`, returns the OS-assigned port. For Unix, returns
    /// the socket path.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot report the local address.
    pub fn bound_endpoint(&self) -> io::Result<CommandMediatorEndpoint> {
        match &self.inner {
            GatewayInner::Tcp(l) => Ok(CommandMediatorEndpoint::Tcp {
                addr: l.local_addr()?,
            }),
            #[cfg(unix)]
            GatewayInner::Unix(_, path) => Ok(CommandMediatorEndpoint::Unix { path: path.clone() }),
        }
    }

    /// Accept and serve `secret.resolve` connections indefinitely.
    ///
    /// Each connection is dispatched on a dedicated thread. The loop exits when
    /// the listener socket is closed or a fatal accept error occurs. The caller
    /// retains ownership; `Drop` removes the socket file after this returns.
    pub fn serve_forever(&self, store: &Arc<ArcSwap<SecretStore>>) {
        match &self.inner {
            GatewayInner::Tcp(listener) => serve_tcp(listener, store),
            #[cfg(unix)]
            GatewayInner::Unix(listener, _) => serve_unix(listener, store),
        }
    }
}

impl Drop for SecretGatewayListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let GatewayInner::Unix(_, path) = &self.inner {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn serve_tcp(listener: &TcpListener, store: &Arc<ArcSwap<SecretStore>>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let write = match stream.try_clone() {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::warn!(error = %e, "secret gateway: failed to clone TCP stream");
                        continue;
                    }
                };
                let store = Arc::clone(store);
                std::thread::spawn(move || {
                    if let Err(e) = handle_protocol(BufReader::new(stream), write, &store) {
                        tracing::warn!(error = %e, "secret gateway TCP connection error");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "secret gateway TCP accept loop stopped");
                break;
            }
        }
    }
}

#[cfg(unix)]
fn serve_unix(listener: &UnixListener, store: &Arc<ArcSwap<SecretStore>>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let write = match stream.try_clone() {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::warn!(error = %e, "secret gateway: failed to clone Unix stream");
                        continue;
                    }
                };
                let store = Arc::clone(store);
                std::thread::spawn(move || {
                    if let Err(e) = handle_protocol(BufReader::new(stream), write, &store) {
                        tracing::warn!(error = %e, "secret gateway Unix connection error");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "secret gateway Unix accept loop stopped");
                break;
            }
        }
    }
}

fn handle_protocol<R: io::Read, W: io::Write>(
    mut reader: BufReader<R>,
    mut writer: W,
    store: &ArcSwap<SecretStore>,
) -> io::Result<()> {
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if line.len() > MAX_REQUEST_BYTES {
        return write_response(
            &mut writer,
            &ResolveResponse::Err {
                error: "request too large".to_owned(),
            },
        );
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty gateway request",
        ));
    }

    let request = match serde_json::from_str::<ResolveRequest>(trimmed) {
        Ok(r) => r,
        Err(e) => {
            return write_response(
                &mut writer,
                &ResolveResponse::Err {
                    error: format!("malformed request: {e}"),
                },
            );
        }
    };

    tracing::debug!(
        placeholder = %request.placeholder,
        domain = ?request.domain,
        "secret gateway: resolving placeholder"
    );

    let secret_b64 = {
        let snapshot = store.load();
        snapshot
            .resolve(&request.placeholder)
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
    };

    match secret_b64 {
        Some(b64) => write_response(&mut writer, &ResolveResponse::Ok { secret_b64: b64 }),
        None => write_response(
            &mut writer,
            &ResolveResponse::Err {
                error: format!("unknown placeholder: {}", request.placeholder),
            },
        ),
    }
}

fn write_response(writer: &mut impl io::Write, response: &ResolveResponse) -> io::Result<()> {
    let mut payload = serde_json::to_vec(response)
        .map_err(|e| io::Error::other(format!("failed to serialize gateway response: {e}")))?;
    payload.push(b'\n');
    writer.write_all(&payload)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::thread;

    use super::*;
    use crate::secret::{Placeholder, SecretValue};

    fn store_with(placeholder: &str, secret: &[u8]) -> Arc<ArcSwap<SecretStore>> {
        let mut store = SecretStore::new();
        store.insert(
            Placeholder::parse(placeholder).expect("valid placeholder in test fixture"),
            SecretValue::new(secret.to_vec()),
        );
        Arc::new(ArcSwap::from_pointee(store))
    }

    /// Bind a TCP gateway on a loopback port assigned by the OS and return the
    /// listener together with the actual bound address.
    fn bind_tcp() -> (SecretGatewayListener, SocketAddr) {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid loopback addr"),
        };
        let listener = SecretGatewayListener::bind(&endpoint).expect("bind");
        let CommandMediatorEndpoint::Tcp { addr } =
            listener.bound_endpoint().expect("bound_endpoint")
        else {
            panic!("TCP gateway must return a TCP endpoint");
        };
        (listener, addr)
    }

    fn resolve(addr: SocketAddr, placeholder: &str) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let req = serde_json::json!({ "placeholder": placeholder });
        stream
            .write_all(format!("{req}\n").as_bytes())
            .expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        line.trim().to_owned()
    }

    #[test]
    fn known_placeholder_resolves_to_base64_secret() {
        let store = store_with("firma-secret://bw/token", b"ghp_abc");
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = resolve(addr, "firma-secret://bw/token");
        let val: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        let b64 = val["secret_b64"].as_str().expect("secret_b64 field");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        assert_eq!(decoded, b"ghp_abc");
    }

    #[test]
    fn unknown_placeholder_returns_error() {
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = resolve(addr, "firma-secret://bw/absent");
        let val: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert!(val["error"].as_str().is_some(), "raw: {response}");
    }

    #[test]
    fn malformed_request_returns_error() {
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.write_all(b"not json at all\n").expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");

        let val: serde_json::Value =
            serde_json::from_str(line.trim()).expect("valid JSON error response");
        assert!(val["error"].as_str().is_some(), "raw: {line}");
    }

    #[test]
    fn bound_endpoint_returns_assigned_tcp_port() {
        let (listener, addr) = bind_tcp();
        assert_ne!(addr.port(), 0, "OS must assign a non-zero port");
        drop(listener);
    }
}
