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
use std::process::Command;

use firma_authority::AuthorityConfig;
use firma_config_loader::{CONFIG_FILE_NAME, FirmaConfig};
#[cfg(unix)]
use firma_process_orchestrator::UnixEndpoint;
use firma_process_orchestrator::{
    ComponentEndpoint, ComponentPlanContext, ComponentSpec, OrchestratorError, StackTopology,
};
use firma_sidecar::config::{InterceptorMode, SidecarConfig};
use tracing::debug;

use crate::config::StackConfig;
use crate::error::StackError;

/// Resolve the unified config for the stack.
///
/// An explicit `--config` path takes precedence; otherwise
/// `firma-config-loader` discovery is used.
///
/// # Errors
///
/// Returns [`StackError::ConfigResolution`] when a selected configuration cannot be
/// resolved, or [`StackError::ConfigNotFound`] when discovery finds no `firma.toml`.
pub fn resolve_stack_config(cli_override: Option<&Path>) -> Result<StackConfig, StackError> {
    let resolved = firma_config_loader::ConfigResolver::default()
        .resolve_config(cli_override)
        .map_err(|source| StackError::ConfigResolution { source })?
        .ok_or_else(|| StackError::ConfigNotFound {
            path: cli_override.map_or_else(|| PathBuf::from(CONFIG_FILE_NAME), Path::to_path_buf),
        })?;
    debug!(config = %resolved.config_file().display(), "resolved unified firma.toml");
    Ok(StackConfig {
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
pub fn topology() -> Result<StackTopology, OrchestratorError> {
    StackTopology::new([AUTHORITY_NAME, SIDECAR_NAME])
}

/// Firma-specific staged component planner.
///
/// Preparation is intentionally lazy so the orchestrator claims the stack
/// generation before reading caller configuration. The first stage validates
/// both component sections before Authority is spawned; later stages reuse
/// those validated launch inputs.
pub struct ComponentPlanner<'a> {
    cfg: &'a StackConfig,
    prepared: Option<PreparedPlan>,
}

struct PreparedPlan {
    authority_bind_addr: SocketAddr,
    sidecar_endpoint: ComponentEndpoint,
    sidecar_authority_configured: bool,
    executable: PathBuf,
}

impl<'a> ComponentPlanner<'a> {
    pub const fn new(cfg: &'a StackConfig) -> Self {
        Self {
            cfg,
            prepared: None,
        }
    }

    /// Build one complete caller-owned command immediately before its spawn.
    ///
    /// # Errors
    ///
    /// Returns a typed config or staged-planning error. A Sidecar-stage failure
    /// is returned after Authority readiness and is rolled back by the generic
    /// startup transaction.
    pub fn build(
        &mut self,
        context: &ComponentPlanContext<'_>,
    ) -> Result<ComponentSpec, StackError> {
        match context.name() {
            AUTHORITY_NAME => {
                let prepared = PreparedPlan::read(self.cfg)?;
                let mut authority = Command::new(&prepared.executable);
                authority
                    .arg(AUTHORITY_NAME)
                    .arg("--config")
                    .arg(&self.cfg.config_file);
                let authority_publication =
                    context.child_published(ComponentEndpoint::Tcp(prepared.authority_bind_addr));
                authority
                    .arg("--startup-report")
                    .arg(authority_publication.startup_report_path());
                self.prepared = Some(prepared);
                Ok(ComponentSpec {
                    command: authority,
                    readiness: authority_publication.into_readiness(),
                })
            }
            SIDECAR_NAME => {
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or(StackError::MissingReadyEndpoint {
                        component: AUTHORITY_NAME,
                    })?;
                let sidecar_publication =
                    context.child_published(prepared.sidecar_endpoint.clone());
                let authority_connect_addr = if prepared.authority_bind_addr.port() == 0
                    && prepared.sidecar_authority_configured
                {
                    let endpoint = context.ready_endpoint(AUTHORITY_NAME).ok_or(
                        StackError::MissingReadyEndpoint {
                            component: AUTHORITY_NAME,
                        },
                    )?;
                    #[cfg(unix)]
                    let addr = match endpoint {
                        ComponentEndpoint::Tcp(addr) => addr,
                        ComponentEndpoint::Unix(_) => {
                            return Err(StackError::Orchestrator(OrchestratorError::Platform(
                                "Authority published a non-TCP endpoint".to_string(),
                            )));
                        }
                    };
                    #[cfg(windows)]
                    let ComponentEndpoint::Tcp(addr) = endpoint;
                    Some(*addr)
                } else {
                    None
                };
                let mut sidecar = Command::new(&prepared.executable);
                sidecar
                    .arg(SIDECAR_NAME)
                    .arg("--config")
                    .arg(&self.cfg.config_file);
                if let Some(connect_addr) = authority_connect_addr {
                    sidecar
                        .arg("--authority-connect-addr")
                        .arg(connect_addr.to_string());
                }
                sidecar
                    .arg("--startup-report")
                    .arg(sidecar_publication.startup_report_path());
                Ok(ComponentSpec {
                    command: sidecar,
                    readiness: sidecar_publication.into_readiness(),
                })
            }
            other => Err(StackError::Orchestrator(
                OrchestratorError::InvalidComponentName {
                    name: other.to_string(),
                },
            )),
        }
    }
}

impl PreparedPlan {
    fn read(cfg: &StackConfig) -> Result<Self, StackError> {
        let config = FirmaToml::read(&cfg.config_file)?;
        let authority_bind_addr = config.authority_listen_addr()?;
        let sidecar_config = config.sidecar_config()?;
        let sidecar_endpoint = match sidecar_config.interceptor.mode {
            InterceptorMode::HttpProxy | InterceptorMode::Grpc => {
                ComponentEndpoint::Tcp(sidecar_config.interceptor.listen_addr)
            }
            #[cfg(unix)]
            InterceptorMode::UnixSocket => {
                let path = sidecar_config
                    .interceptor
                    .socket_path
                    .clone()
                    .ok_or_else(|| StackError::ConfigValidation {
                        source: anyhow::anyhow!("validated Unix interceptor has no socket path"),
                    })?;
                ComponentEndpoint::Unix(UnixEndpoint::new(path).map_err(|path| {
                    StackError::ConfigValidation {
                        source: anyhow::anyhow!(
                            "Unix interceptor socket path is not valid UTF-8: {}",
                            path.display()
                        ),
                    }
                })?)
            }
        };
        let sidecar_authority_configured = sidecar_config.authority.url.is_some();
        let executable = match &cfg.firma_bin {
            Some(path) => path.clone(),
            None => std::env::current_exe()
                .map_err(|source| StackError::CurrentExecutable { source })?,
        };
        Ok(Self {
            authority_bind_addr,
            sidecar_endpoint,
            sidecar_authority_configured,
            executable,
        })
    }
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
    /// Returns [`StackError::ConfigValidation`] when the file cannot be read or is not
    /// valid TOML.
    pub fn read(config_path: &Path) -> Result<Self, StackError> {
        let config = FirmaConfig::load(config_path)
            .map_err(|source| StackError::ConfigValidation { source })?;
        Ok(Self { config })
    }

    /// Deserialize Authority configuration and resolve its listen address.
    ///
    /// Using [`AuthorityConfig`] keeps the plan aligned with the Authority's
    /// own schema and defaults.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the `[authority]` section is
    /// missing, does not deserialize, or holds an invalid socket address.
    pub fn authority_listen_addr(&self) -> Result<SocketAddr, StackError> {
        let authority: AuthorityConfig = self
            .config
            .section("authority")
            .map_err(|source| StackError::ConfigValidation { source })?;
        authority
            .listen_addr
            .parse::<SocketAddr>()
            .map_err(|source| StackError::InvalidAuthorityListenAddr {
                address: authority.listen_addr,
                source,
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
    /// Returns [`StackError::ConfigValidation`] when the `[sidecar]` section is missing
    /// or does not deserialize.
    pub fn sidecar_config(&self) -> Result<SidecarConfig, StackError> {
        self.config
            .section("sidecar")
            .map_err(|source| StackError::ConfigValidation { source })
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
    }

    #[test]
    fn unresolvable_is_error() {
        let missing = Path::new("/definitely/not/here/firma.toml");
        assert!(resolve_stack_config(Some(missing)).is_err());
    }

    /// Write `body` to a `firma.toml` under a fresh temp dir and parse it.
    fn read(body: &str) -> (tempfile::TempDir, Result<FirmaToml, StackError>) {
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
