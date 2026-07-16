//! Broker-side application of a redact decision to a wrapped tool's streams.
//!
//! Redaction wraps a sanctioned tool `T`. The broker sits between the agent and
//! `T` and rewrites both directions concurrently:
//!
//! - **stdin** (agent → `T`): rehydrate placeholders into real secrets, so `T`
//!   receives the value it needs;
//! - **stdout** (`T` → agent): mask real secrets back into placeholders, so the
//!   agent never sees a raw value it did not already hold as a placeholder.
//!
//! The two directions are independent streams pumped on separate threads. The
//! codec (`raw` or `mcp-jsonrpc`) comes from the decision. This function is
//! I/O-generic so it can be tested over in-memory streams; the real fd wiring
//! (the accept loop and the wrapped `T`) lives in the broker/shim. It is
//! fail-closed: a denied launch or a misrouted intercept decision returns an
//! error before any stream is touched. See
//! `docs/architecture/secrets-interception.md`.

use std::io::{self, Read, Write};
use std::thread;

use firma_core::{SecretMediation, SecretTransform};

use super::SecretStore;
use super::pep::SecretPepOutcome;
use super::transform::Direction;
use super::transform::mcp::stream_mcp_jsonrpc;
use super::transform::raw::stream_raw;

/// Errors from applying a redact decision to a wrapped launch.
#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    /// The launch was denied (fail closed); no stream was wired.
    #[error("launch denied by policy: {0}")]
    Denied(String),
    /// An intercept decision reached the redact path (intercept rewrites a
    /// vault CLI's one-shot output, not a target tool's bidirectional streams).
    #[error("intercept decision is not valid on the redact path")]
    UnexpectedIntercept,
    /// A stream rewrite failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A rewrite thread panicked; treated as fail closed.
    #[error("a redact rewrite thread terminated abnormally")]
    Thread,
}

/// Apply a redact `outcome` to a wrapped tool's four stream ends.
///
/// Rehydrates `agent_stdin` into `tool_stdin` and masks `tool_stdout` into
/// `agent_stdout`, running both directions concurrently. A
/// [`SecretPepOutcome::Passthrough`] copies both directions unchanged.
///
/// # Errors
///
/// Returns [`RedactError`] on a denied launch, a misrouted intercept decision,
/// an I/O error, or a rewrite thread panic. On deny or a misrouted decision no
/// stream is touched.
pub fn run_redact<AR, TW, TR, AW>(
    outcome: &SecretPepOutcome,
    agent_stdin: AR,
    tool_stdin: TW,
    tool_stdout: TR,
    agent_stdout: AW,
    store: &SecretStore,
) -> Result<(), RedactError>
where
    AR: Read + Send,
    TW: Write + Send,
    TR: Read + Send,
    AW: Write + Send,
{
    let transform = match outcome {
        SecretPepOutcome::Deny(reason) => return Err(RedactError::Denied(reason.clone())),
        SecretPepOutcome::Mediate(SecretMediation::Intercept { .. }) => {
            return Err(RedactError::UnexpectedIntercept);
        }
        SecretPepOutcome::Mediate(SecretMediation::Redact { transform }) => Some(*transform),
        SecretPepOutcome::Passthrough => None,
    };

    let mut agent_stdin = agent_stdin;
    let mut tool_stdin = tool_stdin;
    let mut tool_stdout = tool_stdout;
    let mut agent_stdout = agent_stdout;

    thread::scope(|scope| {
        let inbound = scope.spawn(move || {
            pump(
                transform,
                Direction::Rehydrate,
                &mut agent_stdin,
                &mut tool_stdin,
                store,
            )
        });
        let outbound = scope.spawn(move || {
            pump(
                transform,
                Direction::Mask,
                &mut tool_stdout,
                &mut agent_stdout,
                store,
            )
        });

        // Join both before propagating, so neither thread is left detached.
        let inbound = inbound.join().map_err(|_| RedactError::Thread)?;
        let outbound = outbound.join().map_err(|_| RedactError::Thread)?;
        inbound?;
        outbound?;
        Ok(())
    })
}

/// Pump one direction: apply the transform, or copy through when there is no
/// governing directive (passthrough).
fn pump<R: Read, W: Write>(
    transform: Option<SecretTransform>,
    direction: Direction,
    reader: &mut R,
    writer: &mut W,
    store: &SecretStore,
) -> io::Result<()> {
    match transform {
        None => {
            io::copy(reader, writer)?;
            writer.flush()
        }
        Some(SecretTransform::Raw) => stream_raw(reader, writer, store, direction),
        Some(SecretTransform::McpJsonRpc) => stream_mcp_jsonrpc(reader, writer, store, direction),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::secret::{Placeholder, SecretValue};

    fn store_with(name: &str, value: &str) -> (SecretStore, Placeholder) {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bw", name);
        store
            .insert(placeholder.clone(), SecretValue::from(value))
            .expect("insert secret");
        (store, placeholder)
    }

    fn redact(transform: SecretTransform) -> SecretPepOutcome {
        SecretPepOutcome::Mediate(SecretMediation::Redact { transform })
    }

    #[test]
    fn raw_rehydrates_stdin_and_masks_stdout() {
        let (store, token) = store_with("db", "s3cr3t");
        let agent_stdin = format!("pass={token}\n").into_bytes();
        let tool_stdout = b"observed s3cr3t on stdout".to_vec();
        let mut tool_stdin = Vec::new();
        let mut agent_stdout = Vec::new();

        run_redact(
            &redact(SecretTransform::Raw),
            agent_stdin.as_slice(),
            &mut tool_stdin,
            tool_stdout.as_slice(),
            &mut agent_stdout,
            &store,
        )
        .unwrap();

        // Tool received the real secret; agent only ever sees the placeholder.
        assert_eq!(tool_stdin, b"pass=s3cr3t\n");
        assert_eq!(
            agent_stdout,
            format!("observed {token} on stdout").into_bytes()
        );
    }

    #[test]
    fn mcp_rehydrates_and_masks_in_json_context() {
        let (store, token) = store_with("pw", "pa\"ss");
        let agent_stdin = format!("{{\"login\":\"{token}\"}}\n").into_bytes();
        let tool_stdout = serde_json::to_string(&json!({ "echo": "pa\"ss" }))
            .map(|line| format!("{line}\n").into_bytes())
            .unwrap();
        let mut tool_stdin = Vec::new();
        let mut agent_stdout = Vec::new();

        run_redact(
            &redact(SecretTransform::McpJsonRpc),
            agent_stdin.as_slice(),
            &mut tool_stdin,
            tool_stdout.as_slice(),
            &mut agent_stdout,
            &store,
        )
        .unwrap();

        // stdin rehydrated to a valid JSON message carrying the real secret.
        let to_tool: Value =
            serde_json::from_slice(tool_stdin.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(to_tool["login"], json!("pa\"ss"));
        // stdout masked: the escaped secret is replaced by the placeholder.
        let to_agent: Value =
            serde_json::from_slice(agent_stdout.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(to_agent["echo"], json!(token.as_str()));
    }

    #[test]
    fn passthrough_copies_both_directions_unchanged() {
        let store = SecretStore::new();
        let mut tool_stdin = Vec::new();
        let mut agent_stdout = Vec::new();

        run_redact(
            &SecretPepOutcome::Passthrough,
            &b"to tool"[..],
            &mut tool_stdin,
            &b"from tool"[..],
            &mut agent_stdout,
            &store,
        )
        .unwrap();

        assert_eq!(tool_stdin, b"to tool");
        assert_eq!(agent_stdout, b"from tool");
    }

    #[test]
    fn deny_touches_no_stream_and_fails_closed() {
        let store = SecretStore::new();
        let mut tool_stdin = Vec::new();
        let mut agent_stdout = Vec::new();

        let error = run_redact(
            &SecretPepOutcome::Deny("blocked".to_string()),
            &b"to tool"[..],
            &mut tool_stdin,
            &b"from tool"[..],
            &mut agent_stdout,
            &store,
        )
        .unwrap_err();

        assert!(matches!(error, RedactError::Denied(_)));
        assert!(
            tool_stdin.is_empty(),
            "no bytes must reach the tool on deny"
        );
        assert!(
            agent_stdout.is_empty(),
            "no bytes must reach the agent on deny"
        );
    }

    #[test]
    fn intercept_decision_is_rejected_on_redact_path() {
        let store = SecretStore::new();
        let outcome = SecretPepOutcome::Mediate(SecretMediation::Intercept {
            matcher: firma_core::SecretMatcher::Regex {
                pattern: "(?P<name>.)(?P<value>.)".to_string(),
            },
            placeholder: "firma-secret://bw/{name}".to_string(),
        });

        let error =
            run_redact(&outcome, &b""[..], Vec::new(), &b""[..], Vec::new(), &store).unwrap_err();

        assert!(matches!(error, RedactError::UnexpectedIntercept));
    }
}
