//! Wire `firma doctor` CLI args to the doctor module.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::args::doctor::Args;
use crate::doctor::{
    capability_seed, config_parse, firma_bin,
    reachability::{self, Endpoint},
    render,
    report::Report,
    sandbox, state_dirs,
};

/// Entry point for the `firma doctor` subcommand.
///
/// Builds a tokio current-thread runtime, runs all diagnostic checks,
/// renders the report, and exits with:
/// - `0` — all checks are `OK` or `WARN`.
/// - `1` — at least one check is `FAIL`.
/// - `2` — internal error (runtime init, render failure).
pub fn run(args: Args) -> ExitCode {
    info!(
        config = ?args.config,
        state_dir = ?args.state_dir,
        json = args.json,
        timeout_ms = args.timeout_ms,
        "firma doctor starting"
    );

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(error) => {
            eprintln!("firma doctor: tokio runtime: {error}");
            return ExitCode::from(2);
        }
    };

    let RenderedReport(report, json) = runtime.block_on(build_report(args));

    let mut stdout = io::stdout().lock();
    let render_result = if json {
        render::json(&report, &mut stdout)
    } else {
        render::pretty(&report, &mut stdout)
    };
    let _ = stdout.flush();
    if let Err(error) = render_result {
        eprintln!("firma doctor: render: {error}");
        return ExitCode::from(2);
    }

    ExitCode::from(report.exit_code())
}

/// Internal bundle produced by [`build_report`].
///
/// Carries the [`Report`] and the `--json` flag together so both survive
/// the `block_on` call without extra synchronisation.
struct RenderedReport(Report, bool);

#[allow(clippy::too_many_lines)]
async fn build_report(args: Args) -> RenderedReport {
    let mut report = Report::default();
    let timeout = Duration::from_millis(args.timeout_ms);

    // 1. firma binary
    report.push(firma_bin::run());

    // 2. sandbox backends
    let prober = sandbox::CommandProber::new(timeout);
    report.extend(sandbox::check_with(sandbox::OsFamily::current(), &prober).await);

    // 3. config parse — runs early so the reachability probes know which
    //    child configs to load.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config_check = config_parse::check(args.config.as_deref(), &cwd);
    let stack_cfg_path = args
        .config
        .clone()
        .or_else(|| config_parse::find_stack_config(&cwd));
    report.push(config_check);

    let stack_cfg = stack_cfg_path
        .as_deref()
        .and_then(|p| firma_stack::load_stack_config(p).ok());

    // 4. sidecar reachability
    let sidecar_endpoint =
        stack_cfg.as_ref().and_then(
            |cfg| match firma_sidecar::config::SidecarConfig::load_from_path(&cfg.sidecar_config) {
                Ok(sc) => Some(reachability::endpoint_from_sidecar(&sc)),
                Err(error) => {
                    warn!(?error, "could not load sidecar config");
                    None
                }
            },
        );
    report.push(reachability::check_endpoint("sidecar reachable", sidecar_endpoint, timeout).await);

    // 5. authority reachability
    let authority_endpoint: Option<Endpoint> = stack_cfg.as_ref().and_then(|cfg| {
        match firma_authority::config::AuthorityConfig::load(Some(&cfg.authority_config)) {
            Ok(ac) => reachability::endpoint_from_authority(&ac),
            Err(error) => {
                warn!(?error, "could not load authority config");
                None
            }
        }
    });
    report.push(
        reachability::check_endpoint("authority reachable", authority_endpoint, timeout).await,
    );

    // 6. capability seed
    let state_dir = resolve_state_dir(args.state_dir.clone(), stack_cfg.as_ref());
    report.push(capability_seed::check(&state_dir));

    // 7. state directories
    let data_dir = state_dirs::resolve_data_dir(
        std::env::var("XDG_DATA_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        std::env::var("APPDATA").ok().as_deref(),
    );
    report.extend(state_dirs::check(&state_dir, data_dir.as_deref()));

    debug!(
        check_count = report.checks.len(),
        worst = ?report.worst(),
        "doctor report built"
    );
    RenderedReport(report, args.json)
}

/// Resolve the runtime state directory from the CLI flag, the stack config, or
/// the platform default.
///
/// The `unwrap_or_else` fallback is intentional: `firma doctor` must always
/// produce a report rather than fail-close due to a missing state dir. The
/// subsequent `state_dirs::check` will mark an absent directory as `WARN`.
fn resolve_state_dir(
    flag: Option<PathBuf>,
    stack_cfg: Option<&firma_stack::StackConfig>,
) -> PathBuf {
    if let Some(p) = flag {
        return p;
    }
    if let Some(p) = stack_cfg.and_then(|c| c.state_dir.clone()) {
        return p;
    }
    firma_stack::resolve_state_dir(None).unwrap_or_else(|_| PathBuf::from("."))
}
