//! In-sandbox shim: courier the wrapped tool's descriptors to the broker.
//!
//! The shim shadows a configured executable inside the sandbox. It sets up
//! socketpairs for the real tool's stdio, hands the broker the four descriptors
//! it needs via `SCM_RIGHTS` (see [`broker::FdRole`]), then runs the real tool
//! with its stdio routed through the broker. The shim holds no plaintext: the
//! rewriting happens out-of-sandbox in the broker.
//!
//! Only the [`shim::courier`] handshake lives here (it is unit-testable against a
//! real broker socket); the process orchestration (socketpairs, spawn, wait) lives
//! in the `firma-secret-shim` binary.
//!
//! See `docs/architecture/secrets-interception.md`.

use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::broker::{FdRole, Handshake, send_handshake};

/// Env var carrying the broker's Unix-socket path into the sandbox.
pub const BROKER_SOCK_ENV: &str = "FIRMA_RUN_SECRET_BROKER_SOCK";

/// Env var naming the directory that holds the real (un-shimmed) binaries,
/// looked up by the basename of the shim's `argv[0]`.
pub const REAL_DIR_ENV: &str = "FIRMA_RUN_SHIM_REAL_DIR";

/// Connect to the broker at `sock` and courier the wrapped tool's descriptors.
///
/// The four descriptors are sent in [`super::broker::FdRole`] order:
/// `AgentStdinSource`, `ToolStdinSink`, `ToolStdoutSource`, `AgentStdoutSink`.
/// The control connection is closed once the handshake is sent — the broker
/// mediates over the couriered descriptors, not this socket.
///
/// # Errors
///
/// Returns an I/O error if connecting or sending the handshake fails. The caller
/// must fail closed (not run the tool unmediated) on error.
pub fn courier(
    sock: &Path,
    argv: &[String],
    agent_stdin: BorrowedFd<'_>,
    tool_stdin_sink: BorrowedFd<'_>,
    tool_stdout_source: BorrowedFd<'_>,
    agent_stdout: BorrowedFd<'_>,
) -> io::Result<()> {
    let stream = UnixStream::connect(sock)?;
    let handshake = Handshake {
        argv: argv.to_vec(),
        fds: vec![
            FdRole::AgentStdinSource,
            FdRole::ToolStdinSink,
            FdRole::ToolStdoutSource,
            FdRole::AgentStdoutSink,
        ],
    };
    send_handshake(
        &stream,
        &handshake,
        &[
            agent_stdin,
            tool_stdin_sink,
            tool_stdout_source,
            agent_stdout,
        ],
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, OwnedFd};

    use super::*;
    use crate::secret::broker::BrokerListener;

    #[test]
    fn courier_sends_four_roles_and_working_descriptors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("broker.sock");
        let listener = BrokerListener::bind(&sock).expect("bind");

        // Four independent pipes; the broker receives one end of each.
        let (agent_stdin_r, agent_stdin_w) = std::io::pipe().expect("pipe");
        let (tool_stdin_r, tool_stdin_w) = std::io::pipe().expect("pipe");
        let (tool_stdout_r, tool_stdout_w) = std::io::pipe().expect("pipe");
        let (agent_stdout_r, agent_stdout_w) = std::io::pipe().expect("pipe");

        let argv = vec!["bws".to_string(), "secret".to_string()];
        courier(
            &sock,
            &argv,
            agent_stdin_r.as_fd(),
            tool_stdin_w.as_fd(),
            tool_stdout_r.as_fd(),
            agent_stdout_w.as_fd(),
        )
        .expect("courier");

        let accepted = listener.accept().expect("accept");
        assert_eq!(accepted.handshake.argv, argv);
        assert_eq!(
            accepted.handshake.fds,
            [
                FdRole::AgentStdinSource,
                FdRole::ToolStdinSink,
                FdRole::ToolStdoutSource,
                FdRole::AgentStdoutSink,
            ]
        );

        // The couriered ToolStdinSink is a working duplicate: writing to the
        // broker's copy is readable from the tool-side read end.
        let by_role = accepted.into_by_role().expect("by role");
        let mut broker_tool_stdin = std::fs::File::from(
            by_role
                .into_iter()
                .find(|(role, _)| *role == FdRole::ToolStdinSink)
                .map(|(_, fd)| fd)
                .expect("tool stdin sink"),
        );
        drop(tool_stdin_w);
        broker_tool_stdin.write_all(b"secret").expect("write");
        drop(broker_tool_stdin);
        let mut got = String::new();
        std::fs::File::from(OwnedFd::from(tool_stdin_r))
            .read_to_string(&mut got)
            .expect("read");
        assert_eq!(got, "secret");

        drop((agent_stdin_w, tool_stdout_w, agent_stdout_r));
    }
}
