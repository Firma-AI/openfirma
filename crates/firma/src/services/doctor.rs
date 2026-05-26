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
    report::{Check, Report},
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

/// Count per-run sidecars that are currently running, by enumerating the
/// runtime markers `firma sidecar status` consults. Any error (missing run
/// dir, unreadable marker) is treated as "none live" — doctor must never fail
/// because the optional run dir is absent.
fn count_live_per_run_sidecars(runtime_dir: &std::path::Path) -> usize {
    firma_stack::sidecar_markers::list(runtime_dir).map_or(0, |entries| {
        entries
            .iter()
            .filter(|e| marker_state_is_live(e.state))
            .count()
    })
}

/// A per-run marker counts as live when its process is alive. An `http_proxy`
/// per-run sidecar binds a TCP port and has no responding `sidecar.sock`, so
/// its marker is `Unhealthy` (pid alive, UDS probe fails) rather than
/// `Running` — both mean an agent is actively running under it.
fn marker_state_is_live(state: firma_stack::status::State) -> bool {
    use firma_stack::status::State;
    matches!(state, State::Running | State::Unhealthy)
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
    report.extend(sandbox::check_with(&sandbox::HostProbe::current(), &prober).await);

    // 3. config parse — resolves the unified `firma.toml` everyone else
    //    uses, then validates both sections. Runs early so the
    //    reachability probes can reuse the resolved path.
    let resolved_config =
        firma_config::resolve_config("doctor", args.config.as_deref(), &firma_config::SystemDirs);
    let config_path = match &resolved_config {
        Ok(resolved) => {
            let p = resolved.config_file.clone();
            report.push(config_parse::check(&p));
            Some(p)
        }
        Err(error) => {
            report.push(Check::fail(
                "config parsed",
                format!("could not resolve firma.toml: {error}"),
            ));
            None
        }
    };

    // Parse the resolved file once; reachability probes 4 and 5 reuse it.
    let parsed_config =
        config_path
            .as_deref()
            .and_then(|p| match firma_config::FirmaConfig::load(p) {
                Ok(parsed) => Some(parsed),
                Err(error) => {
                    warn!(?error, "could not parse firma.toml");
                    None
                }
            });

    // State dir doubles as the runtime dir on every supported platform, so the
    // per-run sidecar markers live under it. Resolve it now: checks 4 and 5
    // cross-check live per-run instances against the configured daemon probe.
    let state_dir = crate::services::config::resolve_state_dir(args.state_dir.clone())
        .unwrap_or_else(|_| PathBuf::from("."));
    let live_running = count_live_per_run_sidecars(&state_dir);

    // 4. sidecar reachability
    let sidecar_endpoint = parsed_config.as_ref().and_then(|c| {
        match c.section("sidecar").and_then(|body| {
            toml::from_str::<firma_sidecar::config::SidecarConfig>(&body).map_err(|e| e.to_string())
        }) {
            Ok(sc) => Some(reachability::endpoint_from_sidecar(&sc)),
            Err(error) => {
                warn!(?error, "could not load sidecar config");
                None
            }
        }
    });
    let sidecar_daemon =
        reachability::check_endpoint("sidecar reachable", sidecar_endpoint, timeout).await;
    report.push(reachability::reconcile_reachability(
        sidecar_daemon,
        live_running,
    ));

    // 5. authority reachability
    let authority_endpoint: Option<Endpoint> = parsed_config.as_ref().and_then(|c| {
        c.section("authority")
            .ok()
            .and_then(|body| toml::from_str::<firma_authority::AuthorityConfig>(&body).ok())
            .and_then(|ac| reachability::endpoint_from_authority(&ac))
    });
    let authority_daemon =
        reachability::check_endpoint("authority reachable", authority_endpoint, timeout).await;
    report.push(reachability::reconcile_reachability(
        authority_daemon,
        live_running,
    ));

    // 6. capability seed
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

#[cfg(test)]
mod tests {
    use super::*;
    use firma_stack::status::State;

    #[test]
    fn live_includes_running_and_unhealthy_but_not_stopped() {
        // http_proxy per-run sidecars surface as Unhealthy (alive, no UDS).
        assert!(marker_state_is_live(State::Running));
        assert!(marker_state_is_live(State::Unhealthy));
        assert!(!marker_state_is_live(State::Stopped));
        assert!(!marker_state_is_live(State::Unknown));
    }
}
