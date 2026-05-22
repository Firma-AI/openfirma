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
    report.push(reachability::check_endpoint("sidecar reachable", sidecar_endpoint, timeout).await);

    // 5. authority reachability
    let authority_endpoint: Option<Endpoint> = parsed_config.as_ref().and_then(|c| {
        match c.section("authority.server").and_then(|body| {
            toml::from_str::<firma_authority::AuthorityConfig>(&body).map_err(|e| e.to_string())
        }) {
            Ok(ac) => reachability::endpoint_from_authority(&ac),
            Err(_) => None, // agent-remote configs have no [authority.server] — skip
        }
    });
    report.push(
        reachability::check_endpoint("authority reachable", authority_endpoint, timeout).await,
    );

    // 6. capability seed
    let state_dir = crate::services::config::resolve_state_dir(args.state_dir.clone())
        .unwrap_or_else(|_| PathBuf::from("."));
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
