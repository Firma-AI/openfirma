//! Broker accept loop.
//!
//! Owns the listening side of the broker: accept a shim connection, decide the
//! mediation, and serve it. The decision is produced by an injected closure so
//! the loop stays PDP-agnostic and testable; the real caller passes one that
//! calls [`pep::request_secret_decision`].
//!
//! See `docs/architecture/secrets-interception.md`.

use std::sync::Arc;
use std::thread;

use arc_swap::ArcSwap;

use super::SecretStore;
use super::broker::BrokerListener;
use super::pep::SecretPepOutcome;
use super::serve::{ServeError, serve_connection};

/// Accept one shim connection and serve it to completion.
///
/// `decide` maps the wrapped tool's argv to a mediation outcome.
///
/// # Errors
///
/// Returns [`ServeError`] if accepting, decoding, or serving fails.
pub fn accept_and_serve<D>(
    listener: &BrokerListener,
    store: &ArcSwap<SecretStore>,
    decide: &D,
) -> Result<(), ServeError>
where
    D: Fn(&[String]) -> SecretPepOutcome,
{
    let accepted = listener.accept()?;
    let outcome = decide(&accepted.handshake.argv);
    serve_connection(accepted, &outcome, store)
}

/// Serve shim connections until the listener stops accepting.
///
/// Each connection is served on its own thread so a long-lived redact session
/// (an MCP server) does not block new intercept launches. Per-connection errors
/// are logged and do not stop the loop; the loop ends when `accept` fails (for
/// example when the listener is dropped at teardown).
pub fn serve_forever<D>(listener: BrokerListener, store: Arc<ArcSwap<SecretStore>>, decide: Arc<D>)
where
    D: Fn(&[String]) -> SecretPepOutcome + Send + Sync + 'static,
{
    loop {
        let accepted = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "secret broker accept loop stopping");
                break;
            }
        };
        let store = Arc::clone(&store);
        let decide = Arc::clone(&decide);
        thread::spawn(move || {
            let outcome = decide(&accepted.handshake.argv);
            if let Err(error) = serve_connection(accepted, &outcome, &store) {
                tracing::warn!(%error, "secret mediation failed for a shimmed launch");
            }
        });
    }
    drop(listener);
    drop(store);
    drop(decide);
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    use firma_core::{SecretMediation, SecretTransform};

    use super::*;
    use crate::secret::shim::courier;
    use crate::secret::{Placeholder, SecretValue};

    #[test]
    fn accept_and_serve_runs_a_redact_session_end_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("broker.sock");
        let listener = BrokerListener::bind(&sock).expect("bind");

        let mut store = SecretStore::new();
        let token = Placeholder::mint("bw", "db");
        store
            .insert(token.clone(), SecretValue::from("s3cr3t"))
            .expect("insert");
        let store = ArcSwap::from_pointee(store);

        // Peer ends the "agent" and "tool" drive; broker ends are couriered.
        let (agent_stdin_r, agent_stdin_w) = std::io::pipe().expect("pipe");
        let (mut tool_stdin_r, tool_stdin_w) = std::io::pipe().expect("pipe");
        let (tool_stdout_r, tool_stdout_w) = std::io::pipe().expect("pipe");
        let (mut agent_stdout_r, agent_stdout_w) = std::io::pipe().expect("pipe");
        let token_for_driver = token.clone();

        // A driver thread plays both the shim (courier) and the agent+tool I/O.
        let driver = thread::spawn(move || {
            courier(
                &sock,
                &["npx".to_string(), "@playwright/mcp".to_string()],
                agent_stdin_r.as_fd(),
                tool_stdin_w.as_fd(),
                tool_stdout_r.as_fd(),
                agent_stdout_w.as_fd(),
            )
            .expect("courier");
            // Broker holds duplicates now; drop our broker-side ends.
            drop((agent_stdin_r, tool_stdin_w, tool_stdout_r, agent_stdout_w));

            let mut agent_writes = agent_stdin_w;
            agent_writes
                .write_all(format!("login={token_for_driver}\n").as_bytes())
                .expect("write stdin");
            drop(agent_writes);
            let mut tool_writes = tool_stdout_w;
            tool_writes
                .write_all(b"echo s3cr3t\n")
                .expect("write stdout");
            drop(tool_writes);

            let mut to_tool = String::new();
            tool_stdin_r
                .read_to_string(&mut to_tool)
                .expect("read tool");
            let mut to_agent = String::new();
            agent_stdout_r
                .read_to_string(&mut to_agent)
                .expect("read agent");
            (to_tool, to_agent)
        });

        accept_and_serve(&listener, &store, &|_argv: &[String]| {
            SecretPepOutcome::Mediate(SecretMediation::Redact {
                transform: SecretTransform::Raw,
            })
        })
        .expect("serve");

        let (to_tool, to_agent) = driver.join().expect("driver thread");
        assert_eq!(to_tool, "login=s3cr3t\n", "tool receives the real secret");
        assert_eq!(
            to_agent,
            format!("echo {token}\n"),
            "agent only sees the placeholder"
        );
    }
}
