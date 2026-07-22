//! Runner for `firma control`.

use std::process::ExitCode;

use crate::args::control::Args;

/// Runs the interactive policy-control surface.
pub fn run(_args: &Args) -> anyhow::Result<ExitCode> {
    firma_tui::control::run(&firma_tui::control::ControlOptions::default())
}
