//! Firma-specific stack topology and configuration.
//!
//! This module is the sole place in `firma-stack` that knows the concrete
//! `[authority, sidecar]` topology and depends on the component crates
//! (`firma_authority`, `firma_sidecar`, `firma_config_loader`). It parses the
//! unified `firma.toml` through [`FirmaToml`] and turns it into the plain
//! [`ComponentSpec`] data that the generic supervision machinery consumes.
//!
//! Keeping this knowledge in one module draws the seam a later change cuts
//! along when the generic machinery moves into its own crate.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use firma_authority::AuthorityConfig;
use firma_config_loader::{CONFIG_FILE_NAME, FirmaConfig};
use firma_process_orchestrator::{ComponentName, ComponentSpec, Result, StackError};
use firma_sidecar::config::SidecarConfig;
use tracing::debug;

use crate::config::StackConfig;

/// Resolve the unified config for the stack.
///
/// An explicit `--config` path takes precedence; otherwise
/// `firma-config-loader` discovery is used.
///
/// # Errors
///
/// Returns [`StackError::ConfigRead`] when no `firma.toml` can be resolved.
pub fn resolve_stack_config(cli_override: Option<&Path>) -> Result<StackConfig> {
    let resolved = firma_config_loader::ConfigResolver::default()
        .resolve_config(cli_override)
        .map_err(|error| StackError::ConfigRead {
            path: error.path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string()),
        })?
        .ok_or_else(|| StackError::ConfigRead {
            path: cli_override.map_or_else(|| PathBuf::from(CONFIG_FILE_NAME), Path::to_path_buf),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no firma.toml found"),
        })?;
    debug!(config = %resolved.config_file().display(), "resolved unified firma.toml");
    Ok(StackConfig {
        state_dir: None,
        config_file: resolved.config_file().to_path_buf(),
        firma_bin: None,
    })
}

/// Identity of the local policy authority component.
const AUTHORITY_NAME: &str = "authority";
/// Identity of the local enforcement sidecar component.
const SIDECAR_NAME: &str = "sidecar";

/// Return the fixed component names in startup order.
///
/// The persisted-state readers (stop, status, cleanup, and detached handle
/// reconstruction) enumerate the known components through this list so their
/// runtime-state file names stay aligned with the startup plan.
pub fn component_names() -> &'static [&'static str] {
    &[AUTHORITY_NAME, SIDECAR_NAME]
}

/// Build the ordered component startup plan from the unified `firma.toml`.
///
/// Both listen addresses are resolved eagerly, so a malformed or missing
/// `[authority]` or `[sidecar]` section fails before any component spawns. This
/// is a deliberate fail-fast validation: the caller learns of a configuration
/// error without leaving a half-started stack behind.
///
/// # Errors
///
/// Returns [`StackError::Platform`] when the config path is not UTF-8, when the
/// file cannot be read or parsed, or when either component section is missing
/// or holds an invalid listen address.
pub fn build_plan(cfg: &StackConfig) -> Result<Vec<ComponentSpec>> {
    let cfg_path = cfg
        .config_file
        .to_str()
        .ok_or_else(|| StackError::Platform("non-utf8 config path".into()))?;
    let config = FirmaToml::read(&cfg.config_file)?;
    let auth_addr = config.authority_listen_addr()?;
    let side_addr = config.sidecar_config()?.interceptor.listen_addr;
    Ok(vec![
        ComponentSpec {
            name: ComponentName::new(AUTHORITY_NAME),
            args: vec![
                AUTHORITY_NAME.to_string(),
                "--config".to_string(),
                cfg_path.to_string(),
            ],
            readiness_addr: auth_addr,
        },
        ComponentSpec {
            name: ComponentName::new(SIDECAR_NAME),
            args: vec![
                SIDECAR_NAME.to_string(),
                "--config".to_string(),
                cfg_path.to_string(),
            ],
            readiness_addr: side_addr,
        },
    ])
}

/// One parsed unified Firma configuration shared by the plan builder.
///
/// This thin wrapper over [`FirmaConfig`] ensures each accessor deserializes the
/// owning crate's configuration type instead of mirroring schemas or defaults.
#[derive(Debug)]
pub struct FirmaToml {
    config: FirmaConfig,
}

impl FirmaToml {
    /// Parse the unified configuration once for the accessors below.
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
    /// Using [`AuthorityConfig`] keeps the plan aligned with the Authority's
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
    /// Callers use the resulting listen address for readiness. The sidecar
    /// generates its CA material before opening the interceptor port, so a
    /// connectable port already implies CA readiness and no separate CA probe
    /// is needed.
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

    #[test]
    fn resolve_with_explicit_override() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join(CONFIG_FILE_NAME);
        std::fs::write(&p, "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n")
            .expect("write config");
        let cfg = resolve_stack_config(Some(&p)).expect("resolve override");
        assert_eq!(cfg.config_file, p);
        assert!(cfg.state_dir.is_none());
    }

    #[test]
    fn unresolvable_is_error() {
        let missing = Path::new("/definitely/not/here/firma.toml");
        assert!(resolve_stack_config(Some(missing)).is_err());
    }

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
