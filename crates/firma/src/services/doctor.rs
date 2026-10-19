//! Wire `firma doctor` CLI args to the doctor module.

use std::io::{self, IsTerminal as _, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use firma_runtime_state::RuntimeLayout;
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
pub fn run(args: Args, config: Option<&Path>) -> ExitCode {
    info!(
        config = ?config,
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
            crate::output::err(format!("doctor: tokio runtime: {error}"));
            return ExitCode::from(2);
        }
    };

    let RenderedReport(report, json) = runtime.block_on(build_report(args, config));

    let stdout_is_terminal = io::stdout().is_terminal();
    let mut stdout = io::stdout().lock();
    let render_result = if json {
        render::json(&report, &mut stdout)
    } else if stdout_is_terminal {
        render::pretty_for_stdout(&report, &mut stdout)
    } else {
        render::pretty(&report, &mut stdout)
    };
    let _ = stdout.flush();
    if let Err(error) = render_result {
        crate::output::err(format!("doctor: render: {error}"));
        return ExitCode::from(2);
    }

    ExitCode::from(report.exit_code())
}

/// Count per-run sidecars that are currently running, by enumerating the
/// runtime markers `firma sidecar status` consults. Any error (missing run
/// dir, unreadable marker) is treated as "none live" — doctor must never fail
/// because the optional run dir is absent.
fn count_live_per_run_sidecars(runtime_dir: &std::path::Path) -> usize {
    firma_runtime_state::sidecar_markers::list(runtime_dir).map_or(0, |entries| {
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
fn marker_state_is_live(state: firma_runtime_state::status::State) -> bool {
    use firma_runtime_state::status::State;
    matches!(state, State::Running | State::Unhealthy)
}

/// Internal bundle produced by [`build_report`].
///
/// Carries the [`Report`] and the `--json` flag together so both survive
/// the `block_on` call without extra synchronisation.
struct RenderedReport(Report, bool);

/// Resolve the authority reachability endpoint from a raw `[authority]` section
/// body: parse + validate it into a [`firma_authority::AuthorityConfig`], then build the probe
/// endpoint. Returns `None` if it does not parse, validate, or expose an address.
///
/// Only the listen address is read, so the config is built with TLS disabled:
/// a host that has not generated TLS material must still get its reachability
/// probed rather than dropped for a reason that has nothing to do with it.
fn authority_endpoint_from_body(body: &str, state: &RuntimeLayout) -> Option<Endpoint> {
    let config = firma_authority::AuthorityConfigBuilder::from_toml_str(body, state)
        .ok()?
        .without_tls()
        .build()
        .ok()?;
    reachability::endpoint_from_authority(&config)
}

/// Parse and resolve the `[sidecar]` section the way the Sidecar itself will.
///
/// Every failure is a warning rather than a check: the `config parsed` check
/// already reports a broken section, and the probes below simply have nothing
/// to aim at. `runtime_layout` must be the state directory the Sidecar would
/// resolve, so a config whose artifacts are only defaulted still parses here.
fn parse_sidecar_section(
    config: &firma_config_loader::FirmaConfig,
    runtime_layout: &RuntimeLayout,
) -> Option<firma_sidecar::config::SidecarConfig> {
    let body = match config.raw_section("sidecar") {
        Ok(body) => body,
        Err(error) => {
            warn!(?error, "could not load sidecar config");
            return None;
        }
    };
    let schema = match toml::from_str::<firma_config_schema::sidecar::SidecarConfig>(&body) {
        Ok(schema) => schema,
        Err(error) => {
            warn!(?error, "could not parse sidecar config");
            return None;
        }
    };
    match firma_sidecar::config::SidecarConfig::resolve(schema, runtime_layout) {
        Ok(config) => Some(config),
        Err(error) => {
            warn!(?error, "could not validate sidecar config");
            None
        }
    }
}

async fn build_report(args: Args, config: Option<&Path>) -> RenderedReport {
    let mut report = Report::default();
    let timeout = Duration::from_millis(args.timeout_ms);

    // 1. firma binary
    report.push(firma_bin::run());

    // 2. sandbox backends
    let prober = sandbox::CommandProber::new(timeout);
    report.extend(sandbox::check_with(&sandbox::HostProbe::current(), &prober).await);

    // State dir doubles as the runtime dir on every supported platform, so the
    // per-run sidecar markers live under it. Resolve it before the config
    // check: that check validates the `[sidecar]` section the way the Sidecar
    // will, which means resolving the same state-directory defaults.
    let state_dir = crate::services::config::resolve_state_dir(args.state_dir.clone())
        .unwrap_or_else(|_| PathBuf::from("."));
    let runtime_layout = RuntimeLayout::from_root(&state_dir);

    // 3. config parse — resolves the unified `firma.toml` everyone else
    //    uses, then validates both sections. Runs early so the
    //    reachability probes can reuse the resolved path.
    let resolved_config = firma_config_loader::ConfigResolver::default().resolve_config(config);
    let parsed_config = match &resolved_config {
        Ok(Some(resolved)) => {
            report.push(config_parse::check_loaded(
                &resolved.config,
                &runtime_layout,
            ));
            Some(resolved.config.clone())
        }
        Ok(None) => {
            report.push(Check::fail(
                "config parsed",
                "could not resolve firma.toml: no config found",
            ));
            None
        }
        Err(error) => {
            report.push(Check::fail(
                "config parsed",
                format!("could not resolve firma.toml: {error}"),
            ));
            None
        }
    };

    // Checks 4 and 5 cross-check live per-run instances against the configured
    // daemon probe.
    let live_running = count_live_per_run_sidecars(&state_dir);

    // 4. sidecar reachability
    let parsed_sidecar = parsed_config
        .as_ref()
        .and_then(|config| parse_sidecar_section(config, &runtime_layout));
    let sidecar_endpoint = parsed_sidecar
        .as_ref()
        .map(|config| reachability::endpoint_from_sidecar(config, &runtime_layout));
    let sidecar_daemon =
        reachability::check_endpoint("sidecar reachable", sidecar_endpoint, timeout).await;
    report.push(reachability::reconcile_reachability(
        sidecar_daemon,
        live_running,
    ));

    // 5. authority reachability
    let authority_endpoint: Option<Endpoint> = parsed_config
        .as_ref()
        .and_then(|c| c.raw_section("authority").ok())
        .and_then(|body| authority_endpoint_from_body(&body, &runtime_layout));
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
    use firma_runtime_state::status::State;

    #[test]
    fn live_includes_running_and_unhealthy_but_not_stopped() {
        // http_proxy per-run sidecars surface as Unhealthy (alive, no UDS).
        assert!(marker_state_is_live(State::Running));
        assert!(marker_state_is_live(State::Unhealthy));
        assert!(!marker_state_is_live(State::Stopped));
        assert!(!marker_state_is_live(State::Unknown));
    }
}
