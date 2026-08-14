use std::path::{Path, PathBuf};

use crate::audit::FirmaAuditTrail;
use crate::scenario::{EnforcementScenario, PhaseOutput};
use crate::setup::ScenarioSetup;

/// A coding assignment: initialize a Cargo crate, write code, and build it.
///
/// Cargo leans on the delete-family syscalls (`rename`, `unlink`, `unlinkat`,
/// `rmdir`) that the managed seccomp baseline used to deny under
/// `filesystem.delete` — atomic renames for build outputs and fingerprint or
/// lockfile cleanup. Denying them returned `EPERM` and broke `cargo build`.
///
/// With the deny removed, those syscalls succeed inside the read-write
/// workspace while the read-only rootfs still blocks deletes elsewhere. The
/// enforcement phase proves the agent can finish the whole init -> code -> build
/// loop under `firma run`, exactly as it does unconfined.
pub struct CargoBuild;

impl CargoBuild {
    /// Path to the compiled debug binary the build must produce.
    fn built_binary(ctx: &ScenarioSetup) -> PathBuf {
        ctx.workspace_dir.join("target/debug").join(CRATE_NAME)
    }

    /// Assert the workspace holds a completed build: a manifest and a runnable
    /// debug binary. Shared by both phases — the build must succeed identically
    /// confined and unconfined.
    fn assert_build_artifacts(ctx: &ScenarioSetup) -> Result<(), anyhow::Error> {
        let manifest = ctx.workspace_dir.join("Cargo.toml");
        anyhow::ensure!(
            manifest.is_file(),
            "expected Cargo.toml in workspace: {}",
            manifest.display()
        );
        let binary = Self::built_binary(ctx);
        anyhow::ensure!(
            is_executable_file(&binary),
            "expected built debug binary: {}",
            binary.display()
        );
        Ok(())
    }
}

impl EnforcementScenario for CargoBuild {
    fn name(&self) -> &'static str {
        "cargo_build"
    }

    fn setup(&mut self, ctx: &mut ScenarioSetup) -> Result<(), anyhow::Error> {
        ctx.firma_config().run()?;
        Ok(())
    }

    /// Wipe the workspace before each phase so the enforcement build cannot pass
    /// on artifacts the baseline build left behind, then re-init git so codex
    /// treats it as a trusted directory (`cargo init --vcs none` leaves the repo
    /// untouched).
    fn before_assert(&self, ctx: &ScenarioSetup) -> Result<(), anyhow::Error> {
        ctx.reset_workspace()?;
        ctx.git_init_workspace()
    }

    fn prompt(&self, _ctx: &ScenarioSetup) -> String {
        format!(
            "You are in an empty project directory. Complete this Rust assignment \
             using the command line:\n\
             1. Run `cargo init --bin --name {CRATE_NAME} --vcs none .` to initialize a binary crate.\n\
             2. Replace `src/main.rs` with a program whose `main` prints the sum of \
             the integers 1 through 10.\n\
             3. Run `cargo build` and make sure it compiles cleanly.\n\
             Do not add any external dependencies."
        )
    }

    fn assert_baseline(
        &self,
        ctx: &ScenarioSetup,
        output: &PhaseOutput,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("agent failed");
        }
        Self::assert_build_artifacts(ctx)
    }

    fn assert_enforcement(
        &self,
        ctx: &ScenarioSetup,
        output: &PhaseOutput,
        _audit: &FirmaAuditTrail,
    ) -> Result<(), anyhow::Error> {
        if !output.agent.success {
            anyhow::bail!("agent failed under enforcement");
        }
        // The core assertion: the build completed under firma run, so every
        // delete-family syscall cargo needed inside the workspace was permitted.
        Self::assert_build_artifacts(ctx)
    }
}

/// True when `path` is a regular file with any execute bit set.
fn is_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Crate the agent is asked to create and build. Fixed so both phases can
/// assert on a deterministic binary path.
const CRATE_NAME: &str = "firma_demo";
