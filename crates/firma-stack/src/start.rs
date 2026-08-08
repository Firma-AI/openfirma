//! Firma-facing startup entry points.
//!
//! These thin wrappers resolve the firma-specific `[authority, sidecar]` plan
//! from a [`StackConfig`] and hand it to the generic
//! [`firma_process_orchestrator`] machinery. They keep the public
//! `firma_stack::` entry paths stable while all process supervision lives in the
//! orchestrator crate.

use std::path::Path;
use std::process::Command;

use firma_process_orchestrator::{
    RunningStack, StackGeneration, StackHandle, spawn_stack_from_plan, start_detached,
    start_foreground_from_plan, supervise_owned_generation_from_plan,
};

use crate::config::StackConfig;
use crate::error::StackError;
use crate::plan;

/// Mode in which [`start`] manages the stack after readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMode {
    /// Supervise in the calling process until interruption or component exit.
    Foreground,
    /// Launch the hidden Firma supervisor and return after handoff.
    Detached,
}

/// Spawn the authority and sidecar stack and wait for readiness.
///
/// Defers to [`spawn_stack_from_plan`], resolving the firma plan from `cfg` only
/// after the stack lock is claimed so an already-running stack is reported
/// before config parsing. The caller must eventually call
/// [`RunningStack::shutdown`] to tear the stack down and collect its children.
///
/// Used by `firma-demo-tui`.
///
/// # Errors
///
/// Returns config, state-directory, lock, spawn, or readiness errors.
pub fn spawn_stack(cfg: &StackConfig, state_dir: &Path) -> Result<RunningStack, StackError> {
    let topology = plan::topology()?;
    spawn_stack_from_plan(&topology, || plan::build_plan(cfg), state_dir).map_err(Into::into)
}

/// Start the authority and sidecar stack.
///
/// Resolves the Firma plan from `cfg` only after the stack lock is claimed
/// (foreground) or in the detached supervisor child.
///
/// # Errors
///
/// Returns config, state directory, spawn, readiness, or detach errors.
pub fn start(
    cfg: &StackConfig,
    state_dir: &Path,
    mode: StartMode,
) -> Result<StackHandle, StackError> {
    let topology = plan::topology()?;
    match mode {
        StartMode::Foreground => {
            start_foreground_from_plan(&topology, || plan::build_plan(cfg), state_dir)
                .map_err(Into::into)
        }
        StartMode::Detached => {
            let executable = std::env::current_exe()
                .map_err(|source| StackError::CurrentExecutable { source })?;
            start_detached(&topology, state_dir, |generation| {
                let mut command = Command::new(executable);
                command
                    .args(["__supervise", "--state-dir"])
                    .arg(state_dir)
                    .arg("--config")
                    .arg(&cfg.config_file)
                    .arg("--generation")
                    .arg(generation.to_string());
                if let Some(firma_bin) = &cfg.firma_bin {
                    command.arg("--firma-bin").arg(firma_bin);
                }
                command
            })
            .map_err(Into::into)
        }
    }
}

/// Spawn and own a detached stack for a launcher-assigned generation.
///
/// Defers to [`supervise_owned_generation_from_plan`], resolving the firma plan
/// from `cfg` only after the stack lock is claimed. This is the hidden
/// `__supervise` entry.
///
/// # Errors
///
/// Returns config, startup, readiness, supervision, termination, or cleanup
/// errors.
#[doc(hidden)]
pub fn supervise_owned_generation(
    cfg: &StackConfig,
    state_dir: &Path,
    generation: StackGeneration,
) -> Result<(), StackError> {
    let topology = plan::topology()?;
    supervise_owned_generation_from_plan(&topology, || plan::build_plan(cfg), state_dir, generation)
        .map_err(Into::into)
}
