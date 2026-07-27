//! Sidecar → firma-run secret resolution gateway.
//!
//! Serves a TCP loopback or Unix domain socket where the Sidecar sends
//! `secret.resolve` requests to look up placeholder tokens by name, and
//! `secret.push` requests to store a secret newly extracted from an
//! intercepted HTTP vault response (the HTTP-origin counterpart of the CLI
//! shim's [`intercept::intercept`]). firma-run is the single source of
//! truth for secrets; the Sidecar fetches/pushes on demand rather than
//! caching secrets persistently.
//!
//! # Protocol (newline-framed JSON)
//!
//! Each request carries an `action` discriminator (mirrors the local-exec
//! governance protocol's `ActionPeek` pattern).
//!
//! `secret.resolve` — the request carries an array of placeholder tokens; the
//! response is a positionally-aligned array of per-token results:
//!
//! ```text
//! → {"action":"secret.resolve","placeholders":["firma-secret://bw/token","firma-secret://bw/other"],"domain":"api.github.com"}
//! ← [{"secret_b64":"...base64..."},{"error":"unknown placeholder: ..."}]
//! ```
//!
//! `secret.push` — the Sidecar has already run its own copy of the matcher
//! against an HTTP vault response, extracted one `(name, value)` pair, and
//! minted the placeholder locally (`firma_secret_provider::mint_placeholder`,
//! from the same `placeholder_template` firma-run resolved and mirrored into
//! the Sidecar's config) so it can substitute the placeholder synchronously
//! into the response body. The gateway stores the already-minted placeholder
//! as-is — it does not re-derive it — so the stored key can never diverge
//! from what the agent actually sees. `domain` is `null`/absent unless the
//! matcher's `domain_path`/`domain_is_url` extracted one from the item, in
//! which case the pushed secret is scoped to it (like a CLI intercept's
//! `domain_path`-derived scope); otherwise the secret resolves for any
//! request host — most HTTP vaults return a credential meant for later use
//! against an unrelated downstream host, not the vault itself:
//!
//! ```text
//! → {"action":"secret.push","placeholder":"firma-secret://aws/dbpass","value_b64":"...","domain":null}
//! ← {"placeholder":"firma-secret://aws/dbpass"}
//! ```
//!
//! Protocol-level errors (malformed request, oversized request, unknown
//! action) are returned as a single JSON object `{"error":"..."}` so they can
//! be distinguished from a well-formed batch/push response.
//!
//! The gateway transport is platform-dependent: a Unix domain socket on Unix
//! targets and a TCP loopback socket on Windows. Consumers discover the bound
//! address via the `FIRMA_SECRET_GATEWAY_ADDR` environment variable set by the
//! orchestrator.

use std::io::{self, BufRead, BufReader};
use std::net::TcpListener;
use std::sync::Arc;

#[cfg(unix)]
use std::{os::unix::net::UnixListener, path::PathBuf};

use arc_swap::ArcSwap;
use base64::Engine as _;
use firma_http::Str;
use firma_secret_provider::{
    GatewayRequest, PlaceholderResult, PushRequest, PushResponse, ResolveRequest,
};

use crate::config::CommandMediatorEndpoint;

use super::{Placeholder, SecretStore, SecretValue};

const MAX_REQUEST_BYTES: usize = 64 * 1024;

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

    /// Accept and serve `secret.resolve` / `secret.push` connections
    /// indefinitely.
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
        return write_error_line(&mut writer, "request too large");
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty gateway request",
        ));
    }

    let req = match serde_json::from_str::<GatewayRequest>(trimmed) {
        Ok(req) => req,
        Err(e) => {
            return write_error_line(&mut writer, &format!("malformed request: {e}"));
        }
    };

    match req {
        GatewayRequest::Resolve(resolve) => handle_resolve(&resolve, &mut writer, store),
        GatewayRequest::Push(push) => handle_push(&push, &mut writer, store),
    }
}

fn write_error_line<W: io::Write>(writer: &mut W, message: &str) -> io::Result<()> {
    write_json_line(
        writer,
        &PlaceholderResult::Err {
            error: Str::from(message),
        },
    )
}

fn handle_resolve<W: io::Write>(
    request: &ResolveRequest,
    writer: &mut W,
    store: &ArcSwap<SecretStore>,
) -> io::Result<()> {
    let snapshot = store.load();
    let results: Vec<PlaceholderResult> = request
        .placeholders
        .iter()
        .map(|placeholder| {
            tracing::debug!(
                %placeholder,
                domain = %request.domain,
                "secret gateway: resolving placeholder"
            );
            snapshot.resolve(placeholder, &request.domain).map_or_else(
                || PlaceholderResult::Err {
                    error: Str::from(format!("unknown placeholder: {placeholder}")),
                },
                |bytes| PlaceholderResult::Ok {
                    secret_b64: Str::from(base64::engine::general_purpose::STANDARD.encode(bytes)),
                },
            )
        })
        .collect();

    write_json_line(writer, &results)
}

/// Handle a `secret.push` request: insert the already-minted placeholder into
/// `store`, scoped to `domain` when present (unscoped/wildcard otherwise,
/// mirroring a CLI intercept whose matcher has no `domain_path`), and return
/// the placeholder so the Sidecar can substitute it into the response body it
/// forwards to the agent.
fn handle_push<W: io::Write>(
    request: &PushRequest,
    writer: &mut W,
    store: &ArcSwap<SecretStore>,
) -> io::Result<()> {
    let Some(placeholder) = Placeholder::parse(&request.placeholder) else {
        return write_json_line(
            writer,
            &PushResponse::Err {
                error: Str::from(format!(
                    "invalid placeholder token '{}'",
                    request.placeholder
                )),
            },
        );
    };

    let value = match base64::engine::general_purpose::STANDARD.decode(&*request.value_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return write_json_line(
                writer,
                &PushResponse::Err {
                    error: Str::from(format!("invalid base64 value: {e}")),
                },
            );
        }
    };

    tracing::debug!(
        placeholder = %placeholder,
        domain = ?request.domain.as_deref(),
        "secret gateway: pushing HTTP-intercepted secret"
    );
    store.rcu(|current| {
        let mut updated = SecretStore::clone(current);
        updated.insert(
            placeholder.clone(),
            request.domain.as_deref().map(str::to_owned),
            SecretValue::new(value.clone()),
        );
        updated
    });

    write_json_line(
        writer,
        &PushResponse::Ok {
            placeholder: Str::from(placeholder.as_str()),
        },
    )
}

fn write_json_line<T: serde::Serialize>(writer: &mut impl io::Write, value: &T) -> io::Result<()> {
    let mut payload = serde_json::to_vec(value)
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

    use firma_http::Str;

    use super::*;
    use crate::secret::{Placeholder, SecretValue};

    fn store_with(placeholder: &str, secret: &[u8]) -> Arc<ArcSwap<SecretStore>> {
        let mut store = SecretStore::new();
        store.insert(
            Placeholder::parse(placeholder).expect("valid placeholder in test fixture"),
            None,
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

    fn send_request<S: serde::Serialize>(addr: SocketAddr, req: &S) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .write_all(serde_json::to_vec(req).expect("serialize").as_slice())
            .expect("write");
        stream.write_all(b"\n").expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        line.trim().to_owned()
    }

    fn resolve_batch(addr: SocketAddr, placeholders: &[&str], domain: &str) -> String {
        send_request(
            addr,
            &GatewayRequest::Resolve(ResolveRequest {
                placeholders: placeholders.iter().map(Str::from).collect(),
                domain: Str::from(domain),
            }),
        )
    }

    #[test]
    fn known_placeholder_resolves_to_base64_secret() {
        let store = store_with("firma-secret://bw/token", b"ghp_abc");
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = resolve_batch(addr, &["firma-secret://bw/token"], "api.github.com");
        let arr: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        let b64 = arr[0]["secret_b64"].as_str().expect("secret_b64 field");
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

        let response = resolve_batch(addr, &["firma-secret://bw/absent"], "api.github.com");
        let arr: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert!(arr[0]["error"].as_str().is_some(), "raw: {response}");
    }

    #[test]
    fn batch_resolves_mix_of_known_and_unknown() {
        let store = store_with("firma-secret://bw/token", b"s3cr3t");
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = resolve_batch(
            addr,
            &["firma-secret://bw/token", "firma-secret://bw/absent"],
            "api.github.com",
        );
        let arr: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert_eq!(arr.as_array().expect("array").len(), 2);
        assert!(
            arr[0]["secret_b64"].as_str().is_some(),
            "first item should resolve"
        );
        assert!(
            arr[1]["error"].as_str().is_some(),
            "second item should error"
        );
    }

    #[test]
    fn domain_scoped_secret_rejected_for_wrong_domain() {
        let mut store = SecretStore::new();
        store.insert(
            Placeholder::parse("firma-secret://bw/token").expect("valid"),
            Some("api.github.com".to_owned()),
            SecretValue::new(b"ghp_secret".to_vec()),
        );
        let store = Arc::new(ArcSwap::from_pointee(store));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = resolve_batch(addr, &["firma-secret://bw/token"], "api.stripe.com");
        let arr: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert!(
            arr[0]["error"].as_str().is_some(),
            "wrong-domain request must not resolve: {response}"
        );
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
    fn unknown_action_returns_error() {
        let _ = tracing_subscriber::fmt::try_init();
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = send_request(addr, &serde_json::json!({"action": "secret.frobnicate"}));
        let val: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert!(val["error"].as_str().is_some(), "raw: {response}");
    }

    #[test]
    fn push_stores_the_given_placeholder_and_makes_it_resolvable() {
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let value_b64 = base64::engine::general_purpose::STANDARD.encode(b"s3cr3t-db-pass");
        let response = send_request(
            addr,
            &GatewayRequest::Push(PushRequest {
                placeholder: Str::from("firma-secret://aws/dbpass"),
                value_b64: Str::from(value_b64),
                domain: Some(Str::from("secretsmanager.us-east-1.amazonaws.com")),
            }),
        );
        let val: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert_eq!(val["placeholder"], "firma-secret://aws/dbpass");

        let resolved = resolve_batch(
            addr,
            &["firma-secret://aws/dbpass"],
            "secretsmanager.us-east-1.amazonaws.com",
        );
        let arr: serde_json::Value = serde_json::from_str(&resolved).expect("valid JSON");
        let b64 = arr[0]["secret_b64"].as_str().expect("secret_b64 field");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        assert_eq!(decoded, b"s3cr3t-db-pass");
    }

    /// A pushed secret with no `domain` (the matcher had no `domain_path`) is
    /// unscoped: it must resolve for a request to a host unrelated to where
    /// it was extracted from, mirroring a CLI intercept with no `domain_path`.
    /// This is the common case for HTTP vaults — the fetched credential is
    /// meant for later use against some other downstream host, not the vault
    /// itself.
    #[test]
    fn push_with_no_domain_resolves_for_any_host() {
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let value_b64 = base64::engine::general_purpose::STANDARD.encode(b"s3cr3t-api-key");
        let response = send_request(
            addr,
            &GatewayRequest::Push(PushRequest {
                placeholder: Str::from("firma-secret://demo-http-vault/api-key"),
                value_b64: Str::from(value_b64),
                domain: None,
            }),
        );
        let val: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert_eq!(val["placeholder"], "firma-secret://demo-http-vault/api-key");

        let resolved = resolve_batch(
            addr,
            &["firma-secret://demo-http-vault/api-key"],
            "some-unrelated-downstream-api.example.com",
        );
        let arr: serde_json::Value = serde_json::from_str(&resolved).expect("valid JSON");
        let b64 = arr[0]["secret_b64"].as_str().expect("secret_b64 field");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        assert_eq!(decoded, b"s3cr3t-api-key");
    }

    #[test]
    fn push_invalid_placeholder_token_returns_error() {
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));
        let (listener, addr) = bind_tcp();
        thread::spawn(move || listener.serve_forever(&store));

        let response = send_request(
            addr,
            &GatewayRequest::Push(PushRequest {
                placeholder: Str::from("not-a-placeholder-token"),
                value_b64: Str::from(base64::engine::general_purpose::STANDARD.encode(b"x")),
                domain: Some(Str::from("example.com")),
            }),
        );
        let val: serde_json::Value = serde_json::from_str(&response).expect("valid JSON");
        assert!(val["error"].as_str().is_some(), "raw: {response}");
    }

    #[test]
    fn bound_endpoint_returns_assigned_tcp_port() {
        let (listener, addr) = bind_tcp();
        assert_ne!(addr.port(), 0, "OS must assign a non-zero port");
        drop(listener);
    }
}
