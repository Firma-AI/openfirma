//! Per-connection broker dispatch.
//!
//! Turns one shim handshake into a secret-mediation session. The broker accepts
//! a shim connection (argv + couriered descriptors), asks
//! the Sidecar for a decision, and applies it here. This module owns the
//! **routing**: it maps the couriered [`broker::FdRole`] descriptors to the
//! stream ends [`session::run_intercept`] and [`redact::run_redact`] expect,
//! and dispatches by decision. It is fail-closed — a deny returns before
//! wiring any stream, and a missing required descriptor is an error.
//!
//! The decision is passed in (not fetched here) so this stays PDP-agnostic and
//! testable over in-process descriptors; the accept loop fetches it via [`pep`].
//!
//! See `docs/architecture/secrets-interception.md`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::thread;

use arc_swap::ArcSwap;
use firma_core::SecretMediation;

use super::SecretStore;
use super::broker::{AcceptedHandshake, FdRole};
use super::pep::SecretPepOutcome;
use super::redact::{RedactError, run_redact};
use super::session::{SessionError, run_intercept};

/// Errors from serving one shim connection.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The launch was denied; no stream was wired (fail closed).
    #[error("launch denied by policy: {0}")]
    Denied(String),
    /// A descriptor the decision requires was not couriered.
    #[error("handshake is missing the {0:?} descriptor")]
    MissingFd(FdRole),
    /// The shared secret store lock was poisoned.
    #[error("secret store lock poisoned")]
    StorePoisoned,
    /// A passthrough copy thread panicked; treated as fail closed.
    #[error("a passthrough copy thread terminated abnormally")]
    Thread,
    /// The intercept session failed.
    #[error(transparent)]
    Intercept(#[from] SessionError),
    /// The redact session failed.
    #[error(transparent)]
    Redact(#[from] RedactError),
    /// A descriptor operation or copy failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Apply a mediation `outcome` to one accepted shim connection.
///
/// Maps the couriered descriptors by [`super::broker::FdRole`] and dispatches:
/// - `Redact` → [`run_redact`] over all four ends;
/// - `Intercept` → [`run_intercept`] on the tool→agent leg, with the agent→tool
///   leg copied through when its descriptors are present;
/// - `Passthrough` → copy every present direction unchanged;
/// - `Deny` → return without wiring anything.
///
/// `store` is shared: intercept takes the write lock (it populates the store),
/// redact takes the read lock for the session (multiple redact sessions can run
/// concurrently, but an intercept write waits for them — a known v1 limitation).
///
/// # Errors
///
/// Returns [`ServeError`] on deny, a missing required descriptor, a poisoned
/// lock, a thread panic, or a session/I/O failure.
pub fn serve_connection(
    accepted: AcceptedHandshake,
    outcome: &SecretPepOutcome,
    store: &ArcSwap<SecretStore>,
) -> Result<(), ServeError> {
    let mut fds = accepted.into_by_role()?;

    match outcome {
        SecretPepOutcome::Deny(reason) => Err(ServeError::Denied(reason.clone())),

        SecretPepOutcome::Mediate(SecretMediation::Redact { .. }) => {
            let agent_stdin = take(&mut fds, FdRole::AgentStdinSource)?;
            let tool_stdin = take(&mut fds, FdRole::ToolStdinSink)?;
            let tool_stdout = take(&mut fds, FdRole::ToolStdoutSource)?;
            let agent_stdout = take(&mut fds, FdRole::AgentStdoutSink)?;

            run_redact(
                outcome,
                agent_stdin,
                tool_stdin,
                tool_stdout,
                agent_stdout,
                store,
            )?;
            Ok(())
        }

        SecretPepOutcome::Mediate(SecretMediation::Intercept { .. }) => {
            let mut tool_stdout = take(&mut fds, FdRole::ToolStdoutSource)?;
            let mut agent_stdout = take(&mut fds, FdRole::AgentStdoutSink)?;
            // A vault CLI usually ignores stdin, but if the shim couriered the
            // agent→tool leg, copy it through unchanged (no rehydration).
            let stdin_leg = pair(&mut fds, FdRole::AgentStdinSource, FdRole::ToolStdinSink);

            thread::scope(|scope| {
                let passthrough = stdin_leg.map(|(mut reader, mut writer)| {
                    scope.spawn(move || io::copy(&mut reader, &mut writer).map(drop))
                });
                let intercept = run_intercept(outcome, &mut tool_stdout, &mut agent_stdout, store);
                if let Some(handle) = passthrough {
                    handle.join().map_err(|_| ServeError::Thread)??;
                }
                intercept.map_err(ServeError::from)
            })
        }

        SecretPepOutcome::Passthrough => {
            let out_leg = pair(&mut fds, FdRole::ToolStdoutSource, FdRole::AgentStdoutSink);
            let in_leg = pair(&mut fds, FdRole::AgentStdinSource, FdRole::ToolStdinSink);
            thread::scope(|scope| {
                // Spawn every present leg first, then join — copying them
                // concurrently avoids one leg blocking on the other's pipe.
                let mut handles = Vec::new();
                for (mut reader, mut writer) in [out_leg, in_leg].into_iter().flatten() {
                    handles.push(scope.spawn(move || io::copy(&mut reader, &mut writer).map(drop)));
                }
                for handle in handles {
                    handle.join().map_err(|_| ServeError::Thread)??;
                }
                Ok(())
            })
        }
    }
}

/// Take the descriptor for a required `role`, or fail closed.
fn take(fds: &mut BTreeMap<FdRole, OwnedFd>, role: FdRole) -> Result<File, ServeError> {
    fds.remove(&role)
        .map(File::from)
        .ok_or(ServeError::MissingFd(role))
}

/// Take a `(source, sink)` descriptor pair if and only if both are present.
fn pair(fds: &mut BTreeMap<FdRole, OwnedFd>, source: FdRole, sink: FdRole) -> Option<(File, File)> {
    match (fds.get(&source), fds.get(&sink)) {
        (Some(_), Some(_)) => {
            let source = fds.remove(&source).map(File::from)?;
            let sink = fds.remove(&sink).map(File::from)?;
            Some((source, sink))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::OwnedFd;

    use firma_core::{SecretMatcher, SecretMediation, SecretTransform};

    use super::*;
    use crate::secret::broker::Handshake;
    use crate::secret::{Placeholder, SecretValue};

    /// A pipe end exposed both as an owned descriptor (handed to the broker) and
    /// as the retained peer end (driven by the test).
    fn os_pipe() -> (OwnedFd, OwnedFd) {
        let (reader, writer) = std::io::pipe().expect("pipe");
        (OwnedFd::from(reader), OwnedFd::from(writer))
    }

    fn store_with(name: &str, value: &str) -> (ArcSwap<SecretStore>, Placeholder) {
        let mut store = SecretStore::new();
        let placeholder = Placeholder::mint("bw", name);
        store
            .insert(placeholder.clone(), SecretValue::from(value))
            .expect("insert secret");
        (ArcSwap::from_pointee(store), placeholder)
    }

    #[test]
    fn redact_wires_all_four_ends() {
        let (store, token) = store_with("db", "s3cr3t");

        // Four pipes; the broker gets one end of each, the test drives the peer.
        let (agent_stdin_r, agent_stdin_w) = os_pipe();
        let (tool_stdin_r, tool_stdin_w) = os_pipe();
        let (tool_stdout_r, tool_stdout_w) = os_pipe();
        let (agent_stdout_r, agent_stdout_w) = os_pipe();

        let accepted = AcceptedHandshake {
            handshake: Handshake {
                argv: vec!["npx".to_string(), "@playwright/mcp".to_string()],
                fds: vec![
                    FdRole::AgentStdinSource,
                    FdRole::ToolStdinSink,
                    FdRole::ToolStdoutSource,
                    FdRole::AgentStdoutSink,
                ],
            },
            fds: vec![agent_stdin_r, tool_stdin_w, tool_stdout_r, agent_stdout_w],
        };

        // Drive the peer ends: send a placeholder on stdin, a raw secret on
        // stdout, then close so the broker's rewriters see EOF.
        let mut agent_writes = File::from(agent_stdin_w);
        agent_writes
            .write_all(format!("login={token}\n").as_bytes())
            .unwrap();
        drop(agent_writes);
        let mut tool_writes = File::from(tool_stdout_w);
        tool_writes.write_all(b"leaked s3cr3t\n").unwrap();
        drop(tool_writes);

        serve_connection(
            accepted,
            &SecretPepOutcome::Mediate(SecretMediation::Redact {
                transform: SecretTransform::Raw,
            }),
            &store,
        )
        .unwrap();

        let mut to_tool = String::new();
        File::from(tool_stdin_r)
            .read_to_string(&mut to_tool)
            .unwrap();
        let mut to_agent = String::new();
        File::from(agent_stdout_r)
            .read_to_string(&mut to_agent)
            .unwrap();

        assert_eq!(to_tool, "login=s3cr3t\n", "tool receives the real secret");
        assert_eq!(
            to_agent,
            format!("leaked {token}\n"),
            "agent only sees the placeholder"
        );
    }

    #[test]
    fn intercept_extracts_stdout_into_store() {
        let store = ArcSwap::from_pointee(SecretStore::new());

        let (tool_stdout_r, tool_stdout_w) = os_pipe();
        let (agent_stdout_r, agent_stdout_w) = os_pipe();

        let accepted = AcceptedHandshake {
            handshake: Handshake {
                argv: vec!["bws".to_string(), "secret".to_string(), "list".to_string()],
                fds: vec![FdRole::ToolStdoutSource, FdRole::AgentStdoutSink],
            },
            fds: vec![tool_stdout_r, agent_stdout_w],
        };

        let mut tool_writes = File::from(tool_stdout_w);
        tool_writes
            .write_all(br#"[{"key":"db","value":"s3cr3t"}]"#)
            .unwrap();
        drop(tool_writes);

        let outcome = SecretPepOutcome::Mediate(SecretMediation::Intercept {
            matcher: SecretMatcher::Json {
                value_path: "$[*].value".to_string(),
                name_path: "$[*].key".to_string(),
            },
            placeholder: "firma-secret://bitwarden/{name}".to_string(),
        });

        serve_connection(accepted, &outcome, &store).unwrap();

        let mut to_agent = Vec::new();
        File::from(agent_stdout_r)
            .read_to_end(&mut to_agent)
            .unwrap();
        let seen: serde_json::Value = serde_json::from_slice(&to_agent).unwrap();
        assert_eq!(seen[0]["value"], "firma-secret://bitwarden/db");
        // The extracted secret is now resolvable from the shared store.
        assert_eq!(
            store.load().resolve("firma-secret://bitwarden/db"),
            Some(&b"s3cr3t"[..])
        );
    }

    #[test]
    fn deny_wires_nothing_and_fails_closed() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let (tool_stdout_r, _tool_stdout_w) = os_pipe();
        let (_agent_stdout_r, agent_stdout_w) = os_pipe();

        let accepted = AcceptedHandshake {
            handshake: Handshake {
                argv: vec!["bws".to_string()],
                fds: vec![FdRole::ToolStdoutSource, FdRole::AgentStdoutSink],
            },
            fds: vec![tool_stdout_r, agent_stdout_w],
        };

        let error = serve_connection(
            accepted,
            &SecretPepOutcome::Deny("blocked".to_string()),
            &store,
        )
        .unwrap_err();
        assert!(matches!(error, ServeError::Denied(_)));
    }

    #[test]
    fn missing_required_descriptor_fails_closed() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let (tool_stdout_r, _w) = os_pipe();

        // A redact decision but only one of the four required descriptors.
        let accepted = AcceptedHandshake {
            handshake: Handshake {
                argv: vec!["npx".to_string()],
                fds: vec![FdRole::ToolStdoutSource],
            },
            fds: vec![tool_stdout_r],
        };

        let error = serve_connection(
            accepted,
            &SecretPepOutcome::Mediate(SecretMediation::Redact {
                transform: SecretTransform::Raw,
            }),
            &store,
        )
        .unwrap_err();
        assert!(matches!(error, ServeError::MissingFd(_)));
    }
}
