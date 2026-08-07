//! Bounded startup evidence for managed components.
//!
//! These probes establish only that startup reached its publication boundary;
//! they do not confer process ownership or promise ongoing health. When supplied,
//! [`StopSignal`] makes each wait cooperatively abortable so startup ownership
//! can roll back promptly after termination.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use firma_authority::AuthorityConfig;
use firma_config_loader::FirmaConfig;
use firma_sidecar::config::SidecarConfig;

use crate::error::{Result, StackError};
use crate::supervisor::StopSignal;

/// Wait until a component accepts a TCP connection or startup must abort.
///
/// A supplied [`StopSignal`] takes precedence over another retry. Callers that
/// do not own process-level signal handling may omit it and remain timeout-bound.
///
/// # Errors
///
/// Returns a termination or [`StackError::Readiness`] error while leaving
/// process rollback to the caller's ownership guard.
pub fn wait_for_tcp(
    component: &str,
    addr: SocketAddr,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        check_startup_stop(stop_signal)?;
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
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

/// Wait until both files constituting generated CA material are present.
///
/// File presence is the Sidecar's startup publication evidence, not a promise
/// that its process remains live. A supplied [`StopSignal`] aborts the wait.
///
/// # Errors
///
/// Returns a termination, filesystem, or [`StackError::Readiness`] error.
pub fn wait_for_ca_material(
    ca_dir: &Path,
    timeout: Duration,
    stop_signal: Option<&StopSignal>,
) -> Result<()> {
    let cert = ca_dir.join("firma-ca.crt");
    let key = ca_dir.join("firma-ca.key");
    let deadline = Instant::now() + timeout;
    loop {
        check_startup_stop(stop_signal)?;
        if cert.exists() && key.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(StackError::Readiness {
                component: "sidecar (CA material)".into(),
                timeout_secs: timeout.as_secs(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
    /// Callers use the resulting listen address for [`wait_for_tcp`] and
    /// [`firma_sidecar::config::HttpsMitmConfig::is_active`] to decide whether
    /// [`wait_for_ca_material`] is required.
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
            "enabled mitm with a host must gate the CA-material probe on"
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
        // Enabled but with no intercept hosts: nothing to intercept, so the
        // CA-material probe must NOT be gated on (the scaffold default).
        let (_dir, parsed) =
            read("[sidecar.interceptor.https_mitm]\nenabled = true\nintercept_hosts = []\n");
        let sidecar = parsed.expect("parses").sidecar_config().expect("sidecar");
        assert!(!sidecar.interceptor.https_mitm.is_active());
    }

    #[test]
    fn wait_for_ca_material_returns_once_both_files_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("firma-ca.crt"), b"cert").expect("write cert");
        std::fs::write(dir.path().join("firma-ca.key"), b"key").expect("write key");

        wait_for_ca_material(dir.path(), Duration::from_secs(1), None).expect("material present");
    }

    #[test]
    fn wait_for_ca_material_times_out_when_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = wait_for_ca_material(dir.path(), Duration::from_millis(0), None)
            .expect_err("absent material must time out");
        assert!(matches!(err, StackError::Readiness { .. }));
    }
}
