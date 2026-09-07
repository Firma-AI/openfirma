//! Canonical resolution and layout of Firma runtime files.
//!
//! Linux uses `XDG_RUNTIME_DIR`. macOS and Windows have no XDG equivalent;
//! the fallback path is `/tmp/firma-$UID` (Unix) or `%LOCALAPPDATA%\firma\runtime`
//! (Windows).

use std::path::{Path, PathBuf};

use firma_identifiers::SandboxId;
use tracing::debug;

use crate::error::Result;

/// Canonical paths rooted at one resolved Firma runtime directory.
///
/// Construct this value once at a process boundary and pass it to code that
/// reads or publishes runtime files. This prevents separate operations from
/// resolving environment variables differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLayout {
    root: PathBuf,
}

/// Inputs consulted, in field order, when resolving a runtime root.
///
/// Every field is an environment value read at a process boundary, so build
/// this from [`Default`] and set only what the caller actually has:
///
/// ```
/// use firma_runtime_state::runtime_paths::RuntimeRootInputs;
///
/// let inputs = RuntimeRootInputs {
///     firma_state_dir: Some("/var/lib/firma".to_string()),
///     ..RuntimeRootInputs::default()
/// };
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RuntimeRootInputs {
    /// Explicit root supplied on the command line; wins over the environment.
    pub flag: Option<PathBuf>,
    /// `FIRMA_STATE_DIR`.
    pub firma_state_dir: Option<String>,
    /// `XDG_RUNTIME_DIR`, used only on Unix.
    pub xdg_runtime_dir: Option<String>,
    /// `LOCALAPPDATA`, used only on Windows.
    pub local_app_data: Option<String>,
    /// `TEMP`, used only on Windows.
    pub temp: Option<String>,
    /// Effective user id, used only by the Unix `/tmp/firma-$UID` fallback.
    pub uid: u32,
}

/// Canonical paths within one `<runtime>/run/<sandbox_id>` entry.
///
/// This layout models the files shared between the per-run Sidecar producer
/// and runtime-state observers. Component-private files remain with their
/// owning crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEntryLayout {
    root: PathBuf,
}

impl RunEntryLayout {
    /// Construct a run-entry layout from an already resolved root.
    #[must_use]
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the run-entry root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Consume the layout and return its run-entry root.
    #[must_use]
    pub fn into_root(self) -> PathBuf {
        self.root
    }

    /// Return the per-run Sidecar Unix socket path.
    #[must_use]
    pub fn sidecar_socket(&self) -> PathBuf {
        self.root.join("sidecar.sock")
    }

    /// Return the generated per-run Sidecar configuration path.
    #[must_use]
    pub fn sidecar_config(&self) -> PathBuf {
        self.root.join("sidecar.toml")
    }

    /// Return the per-run Sidecar PID file path.
    #[must_use]
    pub fn sidecar_pid(&self) -> PathBuf {
        self.root.join("sidecar.pid")
    }

    /// Return the per-run Sidecar metadata path.
    #[must_use]
    pub fn sidecar_metadata(&self) -> PathBuf {
        self.root.join("metadata.toml")
    }

    /// Return the directory holding the per-run Sidecar HTTPS MITM CA.
    #[must_use]
    pub fn ca_dir(&self) -> PathBuf {
        self.root.join(CA_DIR_NAME)
    }

    /// Return the Sidecar MITM CA certificate.
    ///
    /// Public material: wrapped processes must be able to read it to verify
    /// intercepted TLS connections.
    #[must_use]
    pub fn ca_cert(&self) -> PathBuf {
        self.ca_dir().join(CA_CERT_FILE_NAME)
    }

    /// Return the Sidecar MITM CA appended to the host's system roots.
    ///
    /// Written only under `ca_trust_mode = "append_system_roots"`. Public
    /// material, like [`RunEntryLayout::ca_cert`].
    #[must_use]
    pub fn ca_bundle(&self) -> PathBuf {
        self.ca_dir().join(CA_BUNDLE_FILE_NAME)
    }

    /// Return the Sidecar MITM CA private key.
    ///
    /// Secret material. Never expose this path to a wrapped process: holding
    /// the key allows minting certificates trusted by anything configured to
    /// trust the Sidecar CA.
    #[must_use]
    pub fn ca_key(&self) -> PathBuf {
        self.ca_dir().join(CA_KEY_FILE_NAME)
    }
}

/// Directory holding the per-run Sidecar HTTPS MITM CA material.
pub const CA_DIR_NAME: &str = "firma-ca";

/// File name of the Sidecar MITM CA certificate.
pub const CA_CERT_FILE_NAME: &str = "firma-ca.crt";

/// File name of the Sidecar MITM CA appended to the host's system roots.
pub const CA_BUNDLE_FILE_NAME: &str = "firma-ca-bundle.crt";

/// File name of the Sidecar MITM CA private key.
pub const CA_KEY_FILE_NAME: &str = "firma-ca.key";

impl RuntimeLayout {
    /// Resolve a runtime layout from an optional explicit root and the process
    /// environment.
    ///
    /// Resolution order is the explicit root, `FIRMA_STATE_DIR`, and then the
    /// platform runtime-directory convention.
    ///
    /// # Errors
    ///
    /// Returns an error on Windows when neither `LOCALAPPDATA` nor `TEMP` is set.
    pub fn resolve(flag: Option<PathBuf>) -> Result<Self> {
        let layout = Self::resolve_from(RuntimeRootInputs {
            flag,
            firma_state_dir: std::env::var("FIRMA_STATE_DIR").ok(),
            xdg_runtime_dir: std::env::var("XDG_RUNTIME_DIR").ok(),
            local_app_data: std::env::var("LOCALAPPDATA").ok(),
            temp: std::env::var("TEMP").ok(),
            uid: current_uid(),
        })?;
        debug!(path = %layout.root.display(), "resolved runtime layout");
        Ok(layout)
    }

    /// Construct a layout from an already resolved runtime root.
    #[must_use]
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve a layout from explicit environment inputs.
    ///
    /// This pure form is public to support environment-independent integration
    /// tests and embedding processes that resolve their own environment.
    ///
    /// Every resolved root is made absolute against the current working
    /// directory, whichever input produced it. A relative root would otherwise
    /// reach consumers that cannot use one: the sandbox backends pass runtime
    /// paths to bubblewrap, which resolves bind targets against its own root,
    /// and the trust environment handed to a wrapped process is read from a
    /// different working directory than the one `firma run` started in. The
    /// environment variables the platform branches read are as operator-supplied
    /// as the explicit ones, so none of them is exempt.
    #[doc(hidden)]
    pub fn resolve_from(inputs: RuntimeRootInputs) -> Result<Self> {
        let RuntimeRootInputs {
            flag,
            firma_state_dir,
            xdg_runtime_dir,
            local_app_data,
            temp,
            uid,
        } = inputs;
        if let Some(root) = flag {
            return Ok(Self::from_root(absolute_root(&root)?));
        }
        if let Some(root) = firma_state_dir.filter(|value| !value.is_empty()) {
            return Ok(Self::from_root(absolute_root(Path::new(&root))?));
        }

        #[cfg(unix)]
        {
            let _ = (local_app_data, temp);
            let root = xdg_runtime_dir
                .filter(|value| !value.is_empty())
                .map_or_else(
                    || PathBuf::from(format!("/tmp/firma-{uid}")),
                    |xdg| PathBuf::from(xdg).join("firma"),
                );
            Ok(Self::from_root(absolute_root(&root)?))
        }

        #[cfg(windows)]
        {
            let _ = (xdg_runtime_dir, uid);
            if let Some(local) = local_app_data.filter(|value| !value.is_empty()) {
                return Ok(Self::from_root(absolute_root(
                    &PathBuf::from(local).join("firma").join("runtime"),
                )?));
            }
            if let Some(temp) = temp.filter(|value| !value.is_empty()) {
                return Ok(Self::from_root(absolute_root(
                    &PathBuf::from(temp).join("firma"),
                )?));
            }
            Err(crate::RuntimeStateError::StateDirResolve(
                "neither LOCALAPPDATA nor TEMP is set".into(),
            ))
        }
    }

    /// Return the resolved runtime root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Consume the layout and return its runtime root.
    #[must_use]
    pub fn into_root(self) -> PathBuf {
        self.root
    }

    /// Return `<runtime>/capabilities`.
    #[must_use]
    pub fn capabilities_dir(&self) -> PathBuf {
        self.root.join("capabilities")
    }

    /// Return `<runtime>/capabilities/<sandbox_id>.toml`.
    #[must_use]
    pub fn capability_seed(&self, sandbox_id: &SandboxId) -> PathBuf {
        self.capabilities_dir().join(format!("{sandbox_id}.toml"))
    }

    /// Return `<runtime>/run`.
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// Return the canonical layout for `<runtime>/run/<sandbox_id>`.
    #[must_use]
    pub fn run_entry_layout(&self, sandbox_id: &SandboxId) -> RunEntryLayout {
        RunEntryLayout::from_root(self.run_dir().join(sandbox_id.to_string()))
    }

    /// Return the default shared audit log path.
    #[must_use]
    pub fn audit_log(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    /// Return the default long-lived sidecar Unix socket path.
    #[must_use]
    pub fn sidecar_socket(&self) -> PathBuf {
        self.root.join("sidecar.sock")
    }

    /// Return the default persistent enforcement session-state path.
    #[must_use]
    pub fn session_state(&self) -> PathBuf {
        self.root.join("session-state.jsonl")
    }
}

/// Make an operator-supplied runtime root absolute without requiring it to
/// exist yet; the root is created later by the component that owns it.
fn absolute_root(root: &Path) -> Result<PathBuf> {
    std::path::absolute(root).map_err(|error| {
        crate::RuntimeStateError::StateDirResolve(format!(
            "failed to make runtime root '{}' absolute: {error}",
            root.display()
        ))
    })
}

#[cfg(unix)]
fn current_uid() -> u32 {
    nix::unistd::Uid::current().as_raw()
}

#[cfg(windows)]
fn current_uid() -> u32 {
    0
}
