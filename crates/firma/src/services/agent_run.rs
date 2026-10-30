//! `firma run --agent`: resolves a Firma Team Agent, starts a run of
//! it, runs the command as that run, and closes the
//! run with how the run ended.
//!
//! The Control Plane is spoken to inside tokio runtimes that are gone before
//! and after the launch: the launcher is synchronous and mints capabilities on
//! a runtime of its own.

use std::io::IsTerminal as _;
use std::process::ExitCode;

use anyhow::Context as _;
use firma_connection_store::ConnectionStore;
use firma_identifiers::{AgentHandle, RunId};
use firma_login::{
    CloseOutcome, ControlPlaneClient, ControlPlaneError, RecordedOutcome, SessionError,
};
use firma_run::runtime::{ManagedRunInput, RunCompletion, execute_managed_run};

use crate::log::ForegroundLog;

/// Resolves `handle` through the saved login, starts a run of it,
/// runs `command` as that run, and closes the run.
///
/// Every local failure after the run was started is printed before the
/// close; the exit code is the command's own whenever it ran, whatever the
/// close does, except that an agent stopped with its Sidecar never exits 0.
///
/// # Errors
///
/// Returns an error naming what the user can do next when there is no saved
/// login, it cannot provide access, or the Control Plane refuses before an
/// run exists.
pub fn run(
    handle: &AgentHandle,
    command: Vec<String>,
    foreground: &ForegroundLog,
) -> anyhow::Result<ExitCode> {
    // Local refusals come before anything is started on the Control Plane.
    firma_run::identity::reject_reserved_sandbox_id_environment()?;
    firma_run::identity::reject_reserved_session_id_environment()?;
    let (client, input, agent) = crate::block_on_detached(start(handle, command))??;
    let run_id = input.run_id;
    // An agent killed for outliving its stop cannot reset the terminal it
    // owned, so the settings it started from are put back for it.
    let terminal = std::io::stdin()
        .is_terminal()
        .then(crate::services::terminal_mode::save)
        .and_then(Result::ok);
    let completion = crate::services::run::with_terminal_hooks(foreground, |hooks| {
        execute_managed_run(input, hooks)
    });
    if completion.sidecar_stopped {
        reset_terminal(terminal.as_ref());
    }
    report_local_errors(&completion);
    let outcome = closing_outcome(&completion);
    let closed = close(client, run_id, outcome);
    let recorded = closed.as_ref().ok().copied();
    // The agent can exit on its own while its Sidecar, refused by the
    // workspace, is still shutting down; the close then reports the stop.
    let stopped = completion.sidecar_stopped
        || matches!(
            recorded,
            Some(
                RecordedOutcome::AgentDeleted
                    | RecordedOutcome::KeyExpired
                    | RecordedOutcome::Expired
            )
        );
    if stopped {
        eprintln!("{}", stopped_reason(&agent, recorded));
    }
    eprintln!("{}", close_line(outcome, closed));
    Ok(exit_status(&completion, stopped))
}

/// Resolves the Agent and starts a run of it. The client goes on to
/// close the run, so the access token it renewed is reused; the label names
/// the Agent in the messages that follow.
async fn start(
    handle: &AgentHandle,
    command: Vec<String>,
) -> anyhow::Result<(ControlPlaneClient, ManagedRunInput, String)> {
    let store = ConnectionStore::open_existing(firma_connection_store::default_dir()?)
        .context("could not open the saved login")?
        .ok_or(ControlPlaneError::Session(SessionError::MissingConnection))?;
    let mut client = ControlPlaneClient::new(store);
    let agent = client.resolve_agent(handle).await?;
    firma_run::runtime::preflight_managed_run(agent.profile_id)?;
    // The name is any text a Member typed and the Policy Set is not
    // validated: `Debug` quotes them and escapes every control, formatting,
    // and separator character, so neither may drive the terminal. The other
    // values are validated or come from this login.
    eprintln!("Agent:      {} ({})", agent.handle, agent.agent_id);
    eprintln!("Name:       {:?}", agent.name);
    eprintln!("Profile:    {}", agent.profile_id.as_str());
    eprintln!("Policy Set: {:?}", agent.policy_set_id);
    eprintln!("Workspace:  {}", agent.workspace_id);
    eprintln!("Generation: {}", agent.generation);
    let started = client.start_run(handle, &agent.generation).await?;
    eprintln!("Run:  {}", started.run_id);
    eprintln!("Sidecar:    {}", started.sidecar_id);
    let agent_label = format!("{:?} ({})", agent.name, agent.handle);
    let input = ManagedRunInput {
        agent_id: agent.agent_id,
        profile: agent.profile_id,
        run_id: started.run_id,
        sidecar_id: started.sidecar_id,
        workspace_id: agent.workspace_id,
        authority_grpc_uri: agent.authority_grpc_uri,
        capability_public_key: agent.capability_public_key,
        credential: started.credential,
        command,
    };
    Ok((client, input, agent_label))
}

/// Puts back the terminal settings an agent stopped with its Sidecar started
/// from, and turns off the screen modes it may have left on: keyboard
/// enhancement, mouse and focus reporting, bracketed paste and the alternate
/// screen, and shows the cursor again.
///
/// The modes are written to the controlling terminal, the one the agent drew
/// on, wherever stderr goes. Nothing is changed while `firma` runs in the
/// background: the terminal would stop it with SIGTTOU before the close.
#[cfg(unix)]
fn reset_terminal(saved: Option<&crate::services::terminal_mode::Saved>) {
    use std::io::Write as _;

    use nix::unistd::{getpgrp, tcgetpgrp};

    const RESET: &str = "\x1b[<99u\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1004l\
                         \x1b[?2004l\x1b[?1049l\x1b[?25h";
    let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
        return;
    };
    if tcgetpgrp(&tty) != Ok(getpgrp()) {
        return;
    }
    crate::services::terminal_mode::restore_or_warn(saved);
    // Nothing more can be done for a terminal that cannot be written.
    let _ = tty.write_all(RESET.as_bytes()).and_then(|()| tty.flush());
}

/// Puts back the console mode the agent started from.
#[cfg(windows)]
fn reset_terminal(saved: Option<&crate::services::terminal_mode::Saved>) {
    crate::services::terminal_mode::restore_or_warn(saved);
}

/// Why the agent was stopped, from the outcome the Control Plane recorded.
/// A run the workspace had not closed means the Sidecar stopped on its own.
fn stopped_reason(agent: &str, recorded: Option<RecordedOutcome>) -> String {
    match recorded {
        Some(RecordedOutcome::AgentDeleted) => format!(
            "This run of {agent} was stopped because the Agent was deleted from your \
             workspace.\nIf you think this is a mistake, ask a workspace admin."
        ),
        Some(RecordedOutcome::KeyExpired) => {
            format!("This run of {agent} was stopped because the key that started it expired.")
        }
        Some(RecordedOutcome::Expired) => format!(
            "This run of {agent} was stopped because it lost contact with your workspace for \
             too long."
        ),
        Some(RecordedOutcome::Completed | RecordedOutcome::Failed | RecordedOutcome::Cancelled)
        | None => format!(
            "The connection to your workspace stopped, so {agent} was stopped too. You can \
             start the run again."
        ),
    }
}

/// The outcome the CLI asks the Control Plane to record for a run that
/// reached the launch. An agent stopped with its Sidecar did not finish,
/// whatever it exited with.
/// An interrupt after that stop does not make it a cancel.
const fn closing_outcome(completion: &RunCompletion) -> CloseOutcome {
    if completion.sidecar_stopped {
        CloseOutcome::Failed
    } else if completion.interrupted {
        CloseOutcome::Cancelled
    } else if matches!(completion.command, Ok(0)) {
        CloseOutcome::Completed
    } else {
        CloseOutcome::Failed
    }
}

/// The command's own exit code when it ran; 1 otherwise, with the cause
/// already printed, and 1 for a `stopped` agent that exited 0.
fn exit_status(completion: &RunCompletion, stopped: bool) -> ExitCode {
    match completion.command {
        Ok(0) if stopped => ExitCode::from(1),
        Ok(code) => crate::services::run::exit_code(code),
        Err(_) => ExitCode::from(1),
    }
}

fn report_local_errors(completion: &RunCompletion) {
    let failures = [
        completion.command.as_ref().err(),
        completion.shutdown.as_ref().err(),
        completion.teardown.as_ref().err(),
    ];
    for error in failures.into_iter().flatten() {
        crate::output::err(error.to_string());
    }
}

/// Why a close was not confirmed.
enum CloseFailure {
    /// SIGINT or SIGTERM stopped the wait.
    Interrupted,
    /// No runtime to send the request from.
    Runtime(anyhow::Error),
    /// The Control Plane request failed.
    ControlPlane(ControlPlaneError),
}

/// Closes `run_id` as `outcome` on a runtime of its own; the client's
/// connections belonged to the start runtime, so only its session is
/// kept. An access token about to expire is renewed first, out of reach of
/// SIGINT and SIGTERM, which then stop only the close request.
fn close(
    mut client: ControlPlaneClient,
    run_id: RunId,
    outcome: CloseOutcome,
) -> Result<RecordedOutcome, CloseFailure> {
    client.drop_connections();
    let closed = crate::block_on_detached(async {
        client.renew_access().await?;
        tokio::select! {
            // Polled first, so the handlers are installed before the request
            // starts.
            biased;
            () = interrupt() => Ok(None),
            result = client.close_run(run_id, outcome) => result.map(Some),
        }
    });
    match closed {
        Ok(Ok(Some(recorded))) => Ok(recorded),
        Ok(Ok(None)) => Err(CloseFailure::Interrupted),
        Ok(Err(error)) => Err(CloseFailure::ControlPlane(error)),
        Err(error) => Err(CloseFailure::Runtime(error)),
    }
}

/// Resolves on the first SIGINT, or SIGTERM on Unix. A signal that cannot be
/// caught never resolves, so it does not pass for an interrupt.
async fn interrupt() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot catch Ctrl-C during the close");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(error) => {
                tracing::warn!(%error, "cannot catch SIGTERM during the close");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// The stderr line that reports the close: the only report of a failed one.
fn close_line(requested: CloseOutcome, result: Result<RecordedOutcome, CloseFailure>) -> String {
    let requested = RecordedOutcome::from(requested);
    match result {
        Ok(recorded) if recorded == requested => format!("Closed:     {recorded}"),
        Ok(recorded) => format!("Closed:     {recorded} (requested {requested})"),
        Err(failure) => format!(
            "Closed:     unconfirmed ({}); if it is still open, the Control Plane will expire it",
            close_failure_cause(failure)
        ),
    }
}

/// The cause of an unconfirmed close with its full chain: the line is where
/// the error ends.
fn close_failure_cause(failure: CloseFailure) -> String {
    match failure {
        CloseFailure::Interrupted => "interrupted".to_owned(),
        CloseFailure::Runtime(error) => format!("{error:#}"),
        // Its own message advises running the command again, which a close
        // after the command has ended must not.
        CloseFailure::ControlPlane(ControlPlaneError::Unauthorized) => {
            "the Control Plane refused the access token".to_owned()
        }
        CloseFailure::ControlPlane(error) => format!("{:#}", anyhow::Error::from(error)),
    }
}
