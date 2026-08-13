//! Renderer and exit-code mapping for `firma sidecar status`.
//!
//! Exit codes (FIR-104): 0 all running, 1 any unhealthy/stopped,
//! 2 internal error.

// M-CANONICAL-DOCS: module-level doc above; public items documented below.

use std::fmt::Write as _;
use std::process::ExitCode;

use firma_runtime_state::sidecar_markers::SidecarEntry;
use firma_runtime_state::status::State;

use crate::args::sidecar::StatusArgs;

/// Format an uptime duration as `HH:MM:SS`, or `-` when uptime is unknown.
#[must_use]
pub fn format_uptime(secs: Option<u64>) -> String {
    secs.map_or_else(
        || "-".to_string(),
        |s| {
            let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
            format!("{h:02}:{m:02}:{sec:02}")
        },
    )
}

fn state_label(state: State) -> &'static str {
    match state {
        State::Running => "running",
        State::Unhealthy => "unhealthy",
        State::Stopped => "stopped",
        State::Unknown => "unknown",
    }
}

/// Return `0` if every row is [`State::Running`] (or the slice is empty);
/// otherwise return `1`.
#[must_use]
pub fn exit_code_for(rows: &[SidecarEntry]) -> u8 {
    u8::from(!rows.iter().all(|r| r.state == State::Running))
}

/// Render a docker-ps-style fixed-column table including a header row.
#[must_use]
pub fn render_pretty(rows: &[SidecarEntry]) -> String {
    let mut out = format!(
        "{:<13} {:<10} {:<7} {:<10} {:<48} {}\n",
        "SANDBOX_ID", "AGENT", "PID", "STATE", "LISTEN", "UPTIME"
    );
    for r in rows {
        let pid_cell = r.pid.map_or_else(|| "-".to_string(), |pid| pid.to_string());
        let listen_str = r.listen.display().to_string();
        let listen_cell = if listen_str.is_empty() {
            "-"
        } else {
            listen_str.as_str()
        };
        // writeln! avoids the extra allocation from format!+push_str.
        let _ = writeln!(
            out,
            "{:<13} {:<10} {:<7} {:<10} {:<48} {}",
            r.sandbox_id,
            r.agent_id,
            pid_cell,
            state_label(r.state),
            listen_cell,
            format_uptime(r.uptime_secs),
        );
    }
    out
}

/// Run `firma sidecar status`. Maps FIR-104 exit codes onto [`ExitCode`].
///
/// Internal failures print to stderr and map to exit code 2 so the caller
/// does not double-report.
#[expect(
    clippy::unnecessary_wraps,
    reason = "uniform with every other services::*::run returning anyhow::Result<ExitCode>; errors are handled internally and mapped to exit code 2, never propagated"
)]
pub fn run(args: &StatusArgs) -> anyhow::Result<ExitCode> {
    let rows = match collect(args) {
        Ok(rows) => rows,
        Err(e) => {
            crate::output::err(format!("sidecar status: {e}"));
            return Ok(ExitCode::from(2));
        }
    };

    if args.json {
        match serde_json::to_string_pretty(&rows) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                crate::output::err(format!("sidecar status: json: {e}"));
                return Ok(ExitCode::from(2));
            }
        }
    } else {
        print!("{}", render_pretty(&rows));
    }

    Ok(ExitCode::from(exit_code_for(&rows)))
}

fn collect(args: &StatusArgs) -> anyhow::Result<Vec<SidecarEntry>> {
    if args.daemon {
        return collect_daemon();
    }
    let runtime_dir = firma_runtime_state::default_runtime_dir();
    if let Some(id) = &args.sandbox_id {
        return Ok(firma_runtime_state::sidecar_markers::get(&runtime_dir, id)?
            .into_iter()
            .collect());
    }
    Ok(firma_runtime_state::sidecar_markers::list(&runtime_dir)?)
}

/// Probe the long-lived daemon sidecar via the stack status mechanism and
/// project the `sidecar` component into a single [`SidecarEntry`].
///
/// Returns an empty `Vec` when no `sidecar` component is found in the stack
/// status (e.g., the daemon is not running and left no pidfile).
fn collect_daemon() -> anyhow::Result<Vec<SidecarEntry>> {
    let state_dir = firma_runtime_state::resolve_state_dir(None)?;
    let stack = firma_stack::status::status(&state_dir)?;
    let Some(c) = stack.components.into_iter().find(|c| c.name == "sidecar") else {
        return Ok(Vec::new());
    };
    Ok(vec![SidecarEntry {
        sandbox_id: "daemon".to_string(),
        agent_id: "daemon".to_string(),
        session_id: String::new(),
        authority_url: String::new(),
        policy_bundle_version: String::new(),
        pid: c.pid,
        started_at: String::new(),
        state: c.state,
        listen: c.listen.map(endpoint_path).unwrap_or_default(),
        uptime_secs: c.uptime_secs,
    }])
}

#[cfg_attr(
    windows,
    expect(
        clippy::needless_pass_by_value,
        reason = "Option::map transfers the endpoint and Unix consumes its path"
    )
)]
fn endpoint_path(endpoint: firma_stack::ComponentEndpoint) -> std::path::PathBuf {
    match endpoint {
        firma_stack::ComponentEndpoint::Tcp(addr) => std::path::PathBuf::from(addr.to_string()),
        #[cfg(unix)]
        firma_stack::ComponentEndpoint::Unix(path) => path.into_path().into_std_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pretty_assertions::assert_eq;

    use super::*;

    fn make_entry(
        sandbox_id: &str,
        agent_id: &str,
        state: State,
        uptime_secs: Option<u64>,
    ) -> SidecarEntry {
        SidecarEntry {
            sandbox_id: sandbox_id.to_string(),
            agent_id: agent_id.to_string(),
            session_id: String::new(),
            authority_url: String::new(),
            policy_bundle_version: String::new(),
            pid: firma_runtime_state::UserProcessId::new(1234),
            started_at: String::new(),
            state,
            listen: PathBuf::from("/tmp/sidecar.sock"),
            uptime_secs,
        }
    }

    #[test]
    fn format_uptime_zero() {
        assert_eq!(format_uptime(Some(0)), "00:00:00");
    }

    #[test]
    fn format_uptime_862_seconds() {
        assert_eq!(format_uptime(Some(862)), "00:14:22");
    }

    #[test]
    fn format_uptime_3h_11s() {
        assert_eq!(format_uptime(Some(3 * 3600 + 11)), "03:00:11");
    }

    #[test]
    fn format_uptime_none() {
        assert_eq!(format_uptime(None), "-");
    }

    #[test]
    fn exit_code_all_running_is_zero() {
        let rows = vec![
            make_entry("s1", "codex", State::Running, Some(100)),
            make_entry("s2", "codex", State::Running, Some(200)),
        ];
        assert_eq!(exit_code_for(&rows), 0);
    }

    #[test]
    fn exit_code_empty_is_zero() {
        assert_eq!(exit_code_for(&[]), 0);
    }

    #[test]
    fn exit_code_one_unhealthy_among_running_is_one() {
        let rows = vec![
            make_entry("s1", "codex", State::Running, Some(100)),
            make_entry("s2", "codex", State::Unhealthy, Some(200)),
        ];
        assert_eq!(exit_code_for(&rows), 1);
    }

    #[test]
    fn exit_code_stopped_is_one() {
        let rows = vec![make_entry(
            "sbx_01j0000000e008000000000001",
            "codex",
            State::Stopped,
            None,
        )];
        assert_eq!(exit_code_for(&rows), 1);
    }

    #[test]
    fn render_pretty_contains_expected_fields() {
        let rows = vec![make_entry(
            "sbx_01j0000000e008000000000001",
            "codex",
            State::Running,
            Some(862),
        )];
        let output = render_pretty(&rows);

        assert!(
            output.lines().next().unwrap_or("").contains("SANDBOX_ID"),
            "header must contain SANDBOX_ID"
        );
        assert!(output.contains("sbx_"), "must contain sandbox_id");
        assert!(output.contains("codex"), "must contain agent_id");
        assert!(output.contains("running"), "must contain state label");
        assert!(output.contains("00:14:22"), "must contain formatted uptime");
    }

    #[test]
    fn render_pretty_shows_pid_and_listen_for_normal_entry() {
        // make_entry already uses pid 1234 and /tmp/sidecar.sock.
        let rows = vec![make_entry(
            "sbx_01j0000000e008000000000001",
            "codex",
            State::Running,
            Some(0),
        )];
        let output = render_pretty(&rows);
        // The data row is line index 1 (0-indexed).
        let data_row = output.lines().nth(1).unwrap_or("");
        assert!(
            data_row.contains("1234"),
            "data row must contain the PID; row: {data_row:?}"
        );
        assert!(
            data_row.contains("/tmp/sidecar.sock"),
            "data row must contain the LISTEN path; row: {data_row:?}"
        );
    }

    #[test]
    fn render_pretty_dash_for_missing_pid_and_empty_listen() {
        let entry = SidecarEntry {
            sandbox_id: "sbx_01j0000000e008000000000001".to_string(),
            agent_id: "agent".to_string(),
            session_id: String::new(),
            authority_url: String::new(),
            policy_bundle_version: String::new(),
            pid: None,
            started_at: String::new(),
            state: State::Unknown,
            listen: PathBuf::new(),
            uptime_secs: None,
        };
        let output = render_pretty(&[entry]);
        // The data row is line index 1 (0-indexed).
        let data_row = output.lines().nth(1).unwrap_or("");
        assert!(
            data_row.contains(" - "),
            "data row must contain sentinel `-` for missing PID and LISTEN; row: {data_row:?}"
        );
        // A missing PID must not be rendered as a numeric sentinel.
        // The row starts with the sandbox_id column; split on whitespace and
        // check the PID column (third token) is `-`, not `0`.
        let tokens: Vec<&str> = data_row.split_whitespace().collect();
        // tokens: [sandbox_id, agent_id, pid, state, listen, uptime]
        let pid_token = tokens.get(2).copied().unwrap_or("");
        assert_eq!(pid_token, "-", "PID token must be `-`; row: {data_row:?}");
    }

    #[cfg(unix)]
    #[test]
    fn daemon_endpoint_projection_removes_unix_codec_prefix() {
        let path = PathBuf::from("/tmp/firma sidecar.sock");
        assert_eq!(
            endpoint_path(firma_stack::ComponentEndpoint::Unix(
                firma_stack::UnixEndpoint::new(path.clone()).expect("valid Unix socket path")
            )),
            path
        );
        let addr = "127.0.0.1:41000".parse().expect("TCP endpoint");
        assert_eq!(
            endpoint_path(firma_stack::ComponentEndpoint::Tcp(addr)),
            PathBuf::from("127.0.0.1:41000")
        );
    }

    #[test]
    fn exit_code_unknown_is_one() {
        let rows = vec![make_entry(
            "sbx_01j0000000e008000000000001",
            "codex",
            State::Unknown,
            None,
        )];
        assert_eq!(exit_code_for(&rows), 1);
    }
}
