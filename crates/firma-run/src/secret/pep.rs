//! Broker → Sidecar policy-enforcement-point (PEP) client for secret mediation.
//!
//! At each shimmed-tool launch the broker asks the Sidecar (PDP) what to do and
//! receives a [`SecretDecision`]. This module owns that request/response over
//! the governance socket and the **fail-closed** mapping to a
//! [`SecretPepOutcome`]: any transport error, timeout, empty response, or
//! undecodable payload denies the launch rather than running it unmediated.
//!
//! See `docs/architecture/secrets-interception.md`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use firma_core::{SecretDecision, SecretMediation};
use serde::Serialize;

use crate::config::CommandMediatorEndpoint;

/// Governance action discriminator for a secret-mediation decision request.
const SECRET_MEDIATE_ACTION: &str = "secret.mediate";

/// Request the broker sends to the Sidecar for one shimmed-tool launch.
///
/// The Sidecar joins `argv` into the resource id it evaluates `secret.mediate`
/// against, so policies can match with `resource.id like "…"`.
#[derive(Debug, Clone, Serialize)]
pub struct SecretMediationRequest {
    /// Constant governance action discriminator (`secret.mediate`).
    pub action: &'static str,
    /// Wrapped tool's launch argv.
    pub argv: Vec<String>,
    /// Enclosing session identity.
    pub session_id: String,
    /// Agent identity, when known (from `FIRMA_AGENT_ID`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

impl SecretMediationRequest {
    /// Build a request for a launch.
    #[must_use]
    pub fn new(argv: Vec<String>, session_id: String, agent_id: Option<String>) -> Self {
        Self {
            action: SECRET_MEDIATE_ACTION,
            argv,
            session_id,
            agent_id,
        }
    }
}

/// The broker's enforcement outcome for a launch (PEP result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretPepOutcome {
    /// Apply this mediation directive to the launch.
    Mediate(SecretMediation),
    /// No governing policy — run the tool with stdio untouched.
    Passthrough,
    /// Fail closed: block the launch. Carries a human-readable reason.
    Deny(String),
}

/// Ask the Sidecar for a secret-mediation decision, failing closed.
///
/// Any transport error, timeout, empty response, or undecodable payload maps to
/// [`SecretPepOutcome::Deny`] — the launch is blocked rather than run
/// unmediated. A `Mediate` / `Passthrough` decision is returned verbatim.
#[must_use]
pub fn request_secret_decision(
    endpoint: &CommandMediatorEndpoint,
    timeout_ms: u64,
    request: &SecretMediationRequest,
) -> SecretPepOutcome {
    match query(endpoint, timeout_ms, request) {
        Ok(SecretDecision::Mediate(mediation)) => SecretPepOutcome::Mediate(mediation),
        Ok(SecretDecision::Passthrough) => SecretPepOutcome::Passthrough,
        Err(reason) => SecretPepOutcome::Deny(reason),
    }
}

fn query(
    endpoint: &CommandMediatorEndpoint,
    timeout_ms: u64,
    request: &SecretMediationRequest,
) -> Result<SecretDecision, String> {
    let payload = serde_json::to_string(request)
        .map_err(|error| format!("failed to serialize secret-mediation request: {error}"))?;
    let response = match endpoint {
        CommandMediatorEndpoint::Tcp { addr } => send_tcp(*addr, &payload, timeout_ms),
        CommandMediatorEndpoint::Unix { path } => send_unix(path, &payload, timeout_ms),
    }?;
    serde_json::from_str::<SecretDecision>(&response)
        .map_err(|error| format!("failed to decode secret-mediation response: {error}"))
}

fn send_tcp(addr: SocketAddr, payload: &str, timeout_ms: u64) -> Result<String, String> {
    let timeout = Duration::from_millis(timeout_ms);
    let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|error| {
        format!("secret-mediation endpoint unavailable (tcp://{addr}): {error}")
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;
    send_and_receive(stream, payload)
}

fn send_unix(path: &Path, payload: &str, timeout_ms: u64) -> Result<String, String> {
    let timeout = Duration::from_millis(timeout_ms);
    let stream = UnixStream::connect(path).map_err(|error| {
        format!(
            "secret-mediation endpoint unavailable (unix://{}): {error}",
            path.display()
        )
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;
    send_and_receive(stream, payload)
}

fn send_and_receive<T: Write + Read>(mut stream: T, payload: &str) -> Result<String, String> {
    stream
        .write_all(payload.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("secret-mediation request write failed: {error}"))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| format!("secret-mediation response read failed: {error}"))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err("secret-mediation endpoint returned an empty response".to_string());
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    use super::*;

    /// Spawn a one-shot Unix server that reads a request line and writes back
    /// `response`. The socket is bound before the thread starts, so a subsequent
    /// connect never races the bind.
    fn serve_once(path: &Path, response: String) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(path).expect("bind fake governance socket");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader =
                    BufReader::new(stream.try_clone().expect("clone fake governance stream"));
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(b"\n");
            }
        })
    }

    fn sample_request() -> SecretMediationRequest {
        SecretMediationRequest::new(
            vec!["bws".to_string(), "secret".to_string(), "get".to_string()],
            "sess-1".to_string(),
            None,
        )
    }

    #[test]
    fn mediate_decision_maps_to_mediate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gov.sock");
        let directive = SecretMediation::from_annotations(|key| match key {
            "mode" => Some("intercept"),
            "matcher" => Some("json"),
            "match_value" => Some("$[*].value"),
            "match_name" => Some("$[*].key"),
            "placeholder" => Some("firma-secret://bitwarden/{name}"),
            _ => None,
        })
        .expect("valid directive");
        let response = serde_json::to_string(&SecretDecision::Mediate(directive.clone()))
            .expect("serialize decision");
        let server = serve_once(&path, response);

        let outcome = request_secret_decision(
            &CommandMediatorEndpoint::Unix { path },
            1000,
            &sample_request(),
        );
        server.join().expect("server thread");
        assert_eq!(outcome, SecretPepOutcome::Mediate(directive));
    }

    #[test]
    fn passthrough_decision_maps_to_passthrough() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gov.sock");
        let response =
            serde_json::to_string(&SecretDecision::Passthrough).expect("serialize decision");
        let server = serve_once(&path, response);

        let outcome = request_secret_decision(
            &CommandMediatorEndpoint::Unix { path },
            1000,
            &sample_request(),
        );
        server.join().expect("server thread");
        assert_eq!(outcome, SecretPepOutcome::Passthrough);
    }

    #[test]
    fn unreachable_endpoint_fails_closed_to_deny() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.sock");
        let outcome = request_secret_decision(
            &CommandMediatorEndpoint::Unix { path },
            200,
            &sample_request(),
        );
        assert!(matches!(outcome, SecretPepOutcome::Deny(_)));
    }

    #[test]
    fn garbage_response_fails_closed_to_deny() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gov.sock");
        let server = serve_once(&path, "not json".to_string());

        let outcome = request_secret_decision(
            &CommandMediatorEndpoint::Unix { path },
            1000,
            &sample_request(),
        );
        server.join().expect("server thread");
        assert!(matches!(outcome, SecretPepOutcome::Deny(_)));
    }
}
