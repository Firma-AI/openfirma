//! Bounded startup evidence for owned components.
//!
//! These probes establish only that startup reached its publication boundary;
//! they do not confer process ownership or promise ongoing health. Each wait
//! checks the caller's owned-child status before and after observing evidence,
//! closing the race where a dead component could otherwise be declared ready.
//! A supplied [`StopSignal`] also makes the wait cooperatively abortable.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use firma_authority::AuthorityConfig;
use firma_config_loader::FirmaConfig;
use firma_sidecar::config::SidecarConfig;

use crate::error::{Result, StackError};
use crate::supervisor::StopSignal;

/// Wait until a live, owned component accepts a TCP connection.
///
/// The process-status callback must inspect the same [`crate::component::OwnedComponent`]
/// capabilities protected by startup. It runs before each attempt and again
/// after a successful connection so process exit takes precedence over
/// readiness publication.
///
/// # Errors
///
/// Returns termination, collection, [`StackError::ReadinessProcessExited`], or
/// [`StackError::Readiness`] errors while leaving rollback to the owner.
pub fn wait_for_tcp(
    component: &str,
    addr: SocketAddr,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
    mut process_status: impl FnMut() -> Result<Option<(String, ExitStatus)>>,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        check_startup(component, stop_signal, &mut process_status)?;
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            check_startup(component, stop_signal, &mut process_status)?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(StackError::Readiness {
                component: component.to_string(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Reject termination or observed component exit before accepting readiness.
///
/// [`StopSignal`] is checked first so an explicit shutdown request consistently
/// drives rollback even when a component exits concurrently.
fn check_startup(
    _component: &str,
    stop_signal: Option<&StopSignal>,
    process_status: &mut impl FnMut() -> Result<Option<(String, ExitStatus)>>,
) -> Result<()> {
    check_startup_stop(stop_signal)?;
    if let Some((name, status)) = process_status()? {
        return Err(StackError::ReadinessProcessExited {
            component: name,
            status,
        });
    }
    Ok(())
}

/// Convert a process termination request into a rollback-triggering startup error.
fn check_startup_stop(stop_signal: Option<&StopSignal>) -> Result<()> {
    if stop_signal.is_some_and(StopSignal::requested) {
        return Err(StackError::Platform(
            "termination requested during stack startup".into(),
        ));
    }
    Ok(())
}

/// One parsed unified Firma configuration shared by startup probes.
///
/// This thin wrapper over [`FirmaConfig`] ensures each accessor deserializes the
/// owning crate's configuration type instead of mirroring schemas or defaults.
#[derive(Debug)]
pub struct FirmaToml {
    config: FirmaConfig,
}

impl FirmaToml {
    /// Parse the unified configuration once for the probe accessors.
    ///
    /// Component section schemas are validated lazily by their owning accessor.
    ///
    /// # Errors
    ///
    /// Returns [`StackError::Platform`] when the file cannot be read or is not
    /// valid TOML.
    pub fn read(config_path: &Path) -> Result<Self> {
        let config =
            FirmaConfig::load(config_path).map_err(|e| StackError::Platform(format!("{e:#}")))?;
        Ok(Self { config })
    }

    /// Deserialize Authority configuration and resolve its listen address.
    ///
    /// Using [`AuthorityConfig`] keeps readiness aligned with the Authority's
    /// own schema and defaults.
    ///
    /// # Errors
    ///
    /// Returns [`StackError::Platform`] when the `[authority]` section is
    /// missing, does not deserialize, or holds an invalid socket address.
    pub fn authority_listen_addr(&self) -> Result<SocketAddr> {
        let authority: AuthorityConfig = self
            .config
            .section("authority")
            .map_err(|e| StackError::Platform(format!("{e:#}")))?;
        authority.listen_addr.parse::<SocketAddr>().map_err(|e| {
            StackError::Platform(format!(
                "invalid authority listen_addr '{}': {e}",
                authority.listen_addr
            ))
        })
    }

    /// Deserialize Sidecar configuration through [`SidecarConfig`].
    ///
    /// Callers use the resulting listen address for [`wait_for_tcp`]. The
    /// sidecar generates its CA material before opening the interceptor port,
    /// so a connectable port already implies CA readiness and no separate CA
    /// probe is needed.
    ///
    /// # Errors
    ///
    /// Returns [`StackError::Platform`] when the `[sidecar]` section is missing
    /// or does not deserialize.
    pub fn sidecar_config(&self) -> Result<SidecarConfig> {
        self.config
            .section("sidecar")
            .map_err(|e| StackError::Platform(format!("{e:#}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `body` to a `firma.toml` under a fresh temp dir and parse it.
    fn read(body: &str) -> (tempfile::TempDir, Result<FirmaToml>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("firma.toml");
        std::fs::write(&path, body).expect("write config");
        let parsed = FirmaToml::read(&path);
        (dir, parsed)
    }

    const FULL: &str = "\
[authority]
listen_addr = \"127.0.0.1:50051\"

[sidecar.interceptor]
listen_addr = \"127.0.0.1:8080\"

[sidecar.interceptor.https_mitm]
enabled = true
intercept_hosts = [\"api.anthropic.com\"]
";

    #[test]
    fn read_config_parses_all_probe_inputs() {
        let (_dir, parsed) = read(FULL);
        let config = parsed.expect("valid config parses");

        assert_eq!(
            config.authority_listen_addr().expect("authority addr"),
            "127.0.0.1:50051".parse().expect("literal addr")
        );
        let sidecar = config.sidecar_config().expect("sidecar section");
        assert_eq!(
            sidecar.interceptor.listen_addr,
            "127.0.0.1:8080".parse().expect("literal addr")
        );
        assert!(
            sidecar.interceptor.https_mitm.is_active(),
            "enabled mitm with a host must report active"
        );
    }

    #[test]
    fn read_config_rejects_malformed_toml() {
        let (_dir, parsed) = read("this is = = not toml");
        let err = parsed.expect_err("malformed toml must error").to_string();
        assert!(err.contains("firma.toml"), "got: {err}");
    }

    #[test]
    fn read_config_errors_on_missing_file() {
        // The io read failure is surfaced as a StackError before any parsing.
        FirmaToml::read(Path::new("/definitely/not/here/firma.toml"))
            .expect_err("missing file must error");
    }

    #[test]
    fn authority_listen_addr_missing_section_errors() {
        let (_dir, parsed) = read("[sidecar.interceptor]\nlisten_addr = \"127.0.0.1:8080\"\n");
        let err = parsed
            .expect("parses")
            .authority_listen_addr()
            .expect_err("missing [authority] must error")
            .to_string();
        assert!(err.contains("[authority]"), "got: {err}");
    }

    #[test]
    fn authority_listen_addr_invalid_value_errors() {
        let (_dir, parsed) = read("[authority]\nlisten_addr = \"not-an-address\"\n");
        let err = parsed
            .expect("parses")
            .authority_listen_addr()
            .expect_err("bad addr must error")
            .to_string();
        assert!(err.contains("invalid authority listen_addr"), "got: {err}");
    }

    #[test]
    fn sidecar_config_missing_section_errors() {
        let (_dir, parsed) = read("[authority]\nlisten_addr = \"127.0.0.1:50051\"\n");
        let err = parsed
            .expect("parses")
            .sidecar_config()
            .expect_err("missing [sidecar] must error")
            .to_string();
        assert!(err.contains("[sidecar]"), "got: {err}");
    }

    #[test]
    fn sidecar_config_rejects_bad_field() {
        let (_dir, parsed) = read("[sidecar]\nmode = \"not-a-real-mode\"\n");
        let err = parsed
            .expect("parses")
            .sidecar_config()
            .expect_err("bad [sidecar] field must error")
            .to_string();
        assert!(err.contains("invalid `[sidecar]` section"), "got: {err}");
    }

    #[test]
    fn sidecar_config_reports_inactive_mitm() {
        // Enabled but with no intercept hosts: nothing to intercept, so MITM is
        // inactive (the scaffold default).
        let (_dir, parsed) =
            read("[sidecar.interceptor.https_mitm]\nenabled = true\nintercept_hosts = []\n");
        let sidecar = parsed.expect("parses").sidecar_config().expect("sidecar");
        assert!(!sidecar.interceptor.https_mitm.is_active());
    }
}
