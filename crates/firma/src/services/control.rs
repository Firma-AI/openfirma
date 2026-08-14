//! Runner for `firma control`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use firma_authority::AuthorityConfig;
use firma_tui::control::{AuditRow, AuditSourceError, ErrorMessage};

use crate::args::control::Args;
use crate::args::monitor::Decision as MonitorDecision;
use crate::monitor::filters::{AuditLite, decision_matches};
use crate::monitor::tailer::{self, Source as TailSource};

/// Runs Policy Control with stack-derived audit and policy sources.
///
/// The command reuses the same audit log source as `firma monitor` and reads
/// the Authority policy directory from the selected stack config. If no stack
/// config is available, the TUI still opens and reports the missing policy
/// source through normal UI state.
///
/// # Errors
///
/// Returns an error when audit-source setup, config resolution, or terminal UI
/// execution fails.
pub fn run(args: &Args) -> anyhow::Result<ExitCode> {
    let (audit_rows, _audit_guard) = spawn_audit_source(args)?;
    let mut options = firma_tui::control::ControlOptions::with_audit_rows(audit_rows);
    if let Some(policy_dir) = resolve_policy_dir(args.config.as_deref())? {
        options = options.with_policy_dir(policy_dir);
    }

    firma_tui::control::run(&options)
}

#[derive(Debug, thiserror::Error)]
enum PolicyDirResolveError {
    #[error("failed to resolve config for policy discovery")]
    ResolveConfig {
        #[source]
        source: firma_config_loader::ConfigResolveError,
    },
    #[error("failed to load authority config for policy discovery")]
    LoadAuthorityConfig {
        #[source]
        source: firma_authority::config::ConfigError,
    },
}

fn resolve_policy_dir(
    config_override: Option<&Path>,
) -> Result<Option<PathBuf>, PolicyDirResolveError> {
    let Some(resolved) = resolve_control_config(config_override)? else {
        return Ok(None);
    };

    load_authority_policy_dir(&resolved)
}

fn resolve_control_config(
    config_override: Option<&Path>,
) -> Result<Option<firma_config_loader::ResolvedConfig>, PolicyDirResolveError> {
    firma_config_loader::resolve_config(config_override)
        .map_err(|source| PolicyDirResolveError::ResolveConfig { source })
}

fn load_authority_policy_dir(
    resolved: &firma_config_loader::ResolvedConfig,
) -> Result<Option<PathBuf>, PolicyDirResolveError> {
    Ok(AuthorityConfig::from_resolved_section(resolved)
        .map_err(|source| PolicyDirResolveError::LoadAuthorityConfig { source })?
        .map(|config| config.policy_dir))
}

fn spawn_audit_source(args: &Args) -> anyhow::Result<(Receiver<AuditRow>, AuditSourceGuard)> {
    let audit_path = crate::services::config::resolve_audit_log_path(
        args.state_dir.as_ref(),
        args.config.as_deref(),
    )
    .map_err(|error| AuditSourceError::ResolvePath {
        source: ErrorMessage::capture(error),
    })?;

    let (line_tx, line_rx) = channel::<tailer::Line>();
    let (row_tx, row_rx) = channel::<AuditRow>();
    let stop = Arc::new(AtomicBool::new(false));

    let tail_stop = Arc::clone(&stop);
    let tail_handle = thread::spawn(move || {
        tailer::tail(
            audit_path,
            TailSource::Audit,
            None,
            true,
            line_tx,
            tail_stop,
        );
    });

    let forward_stop = Arc::clone(&stop);
    let forward_handle = thread::spawn(move || {
        while !forward_stop.load(Ordering::SeqCst) {
            match line_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let Some(row) = audit_row_from_line(&line) else {
                        continue;
                    };
                    if row_tx.send(row).is_err() {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    Ok((
        row_rx,
        AuditSourceGuard {
            stop,
            handles: vec![tail_handle, forward_handle],
        },
    ))
}

fn audit_row_from_line(line: &tailer::Line) -> Option<AuditRow> {
    if line.source != TailSource::Audit {
        return None;
    }

    let parsed = crate::monitor::filters::audit_passes(&line.raw, None, None, None, None)?;
    audit_row_from_lite(parsed)
}

fn audit_row_from_lite(parsed: AuditLite) -> Option<AuditRow> {
    let decision = if decision_matches(&parsed, MonitorDecision::Allow) {
        firma_tui::control::AuditDecision::Allow
    } else if decision_matches(&parsed, MonitorDecision::Deny) {
        firma_tui::control::AuditDecision::Deny
    } else {
        return None;
    };

    Some(AuditRow {
        time: timestamp_label(parsed.timestamp),
        decision,
        action_class: display_value(parsed.action),
        resource: display_value(parsed.resource),
        policy: display_optional_detail(parsed.deny_reason),
    })
}

fn timestamp_label(timestamp: Option<u128>) -> String {
    let Some(nanos) = timestamp.and_then(|nanos| i64::try_from(nanos).ok()) else {
        return "?".to_string();
    };
    let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(nanos);
    timestamp.format("%H:%M:%S").to_string()
}

fn display_value(value: Option<String>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "?".to_string())
}

fn display_optional_detail(value: Option<String>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

struct AuditSourceGuard {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

impl Drop for AuditSourceGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}
