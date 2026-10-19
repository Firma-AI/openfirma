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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    ///
    /// Defaults to the effective user id of the current process, not to zero:
    /// a caller that fills in only the environment variables it has would
    /// otherwise resolve another user's `/tmp/firma-0`.
    pub uid: u32,
}

impl Default for RuntimeRootInputs {
    fn default() -> Self {
        Self {
            flag: None,
            firma_state_dir: None,
            xdg_runtime_dir: None,
            local_app_data: None,
            temp: None,
            uid: current_uid(),
        }
    }
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
        self.root.join(SIDECAR_SOCKET_FILE_NAME)
    }

    /// Return the generated per-run Sidecar configuration path.
    #[must_use]
    pub fn sidecar_config(&self) -> PathBuf {
        self.root.join(SIDECAR_CONFIG_FILE_NAME)
    }

    /// Return the per-run Sidecar PID file path.
    #[must_use]
    pub fn sidecar_pid(&self) -> PathBuf {
        self.root.join(SIDECAR_PID_FILE_NAME)
    }

    /// Return the per-run Sidecar metadata path.
    #[must_use]
    pub fn sidecar_metadata(&self) -> PathBuf {
        self.root.join(SIDECAR_METADATA_FILE_NAME)
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

/// File name of a Sidecar Unix socket.
const SIDECAR_SOCKET_FILE_NAME: &str = "sidecar.sock";

/// File name of a generated Sidecar configuration.
const SIDECAR_CONFIG_FILE_NAME: &str = "sidecar.toml";

/// File name of a Sidecar PID file.
const SIDECAR_PID_FILE_NAME: &str = "sidecar.pid";

/// File name of the per-run Sidecar metadata.
const SIDECAR_METADATA_FILE_NAME: &str = "metadata.toml";

/// Directory holding the minted capability seeds.
const CAPABILITIES_DIR_NAME: &str = "capabilities";

/// Directory holding the per-run entries.
const RUN_DIR_NAME: &str = "run";

/// File name of the shared audit log.
const AUDIT_LOG_FILE_NAME: &str = "audit.jsonl";

/// File name of the persistent enforcement session state.
const SESSION_STATE_FILE_NAME: &str = "session-state.jsonl";

/// File name of the Authority Ed25519 capability signing key.
const AUTHORITY_KEY_FILE_NAME: &str = "authority.key";

/// File name of the Authority public verification key.
const AUTHORITY_PUBLIC_KEY_FILE_NAME: &str = "authority.pub";

/// File name of the audit signing key.
const AUDIT_KEY_FILE_NAME: &str = "audit.key";

/// File name of the revocation list.
const REVOCATIONS_FILE_NAME: &str = "revocations.txt";

/// Directory holding the Sidecar's generated HTTPS MITM CA outside a per-run
/// entry.
const GENERATED_CA_DIR_NAME: &str = "generated-firma-ca";

/// Environment variable every Firma process resolves its state directory from.
///
/// Exported so the processes that *set* it for a child name the same variable
/// [`RuntimeLayout::resolve`] reads.
pub const STATE_DIR_ENV: &str = "FIRMA_STATE_DIR";

/// Directory holding the Authority TLS material.
const TLS_DIR_NAME: &str = "tls";

/// File name of the Authority server TLS certificate.
const AUTHORITY_TLS_CERTIFICATE_FILE_NAME: &str = "authority.crt";

/// File name of the Authority server TLS private key.
///
/// Deliberately spelled out rather than reusing [`AUTHORITY_KEY_FILE_NAME`]:
/// the two artifacts share a file name but are different keys in different
/// directories, and renaming one must not silently rename the other.
const AUTHORITY_TLS_PRIVATE_KEY_FILE_NAME: &str = "authority.key";

/// File name of the CA certificate a Sidecar verifies the Authority against.
const AUTHORITY_TLS_CA_CERTIFICATE_FILE_NAME: &str = "authority-ca.crt";

/// File name of the CA private key that issues Authority TLS certificates.
const AUTHORITY_TLS_CA_PRIVATE_KEY_FILE_NAME: &str = "authority-ca.key";

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
            firma_state_dir: std::env::var(STATE_DIR_ENV).ok(),
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
        self.root.join(CAPABILITIES_DIR_NAME)
    }

    /// Return `<runtime>/capabilities/<sandbox_id>.toml`.
    #[must_use]
    pub fn capability_seed(&self, sandbox_id: &SandboxId) -> PathBuf {
        self.capabilities_dir().join(format!("{sandbox_id}.toml"))
    }

    /// Return `<runtime>/run`.
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.root.join(RUN_DIR_NAME)
    }

    /// Return the canonical layout for `<runtime>/run/<sandbox_id>`.
    #[must_use]
    pub fn run_entry_layout(&self, sandbox_id: &SandboxId) -> RunEntryLayout {
        RunEntryLayout::from_root(self.run_dir().join(sandbox_id.to_string()))
    }

    /// Return the default shared audit log path.
    #[must_use]
    pub fn audit_log(&self) -> PathBuf {
        self.root.join(AUDIT_LOG_FILE_NAME)
    }

    /// Return the default long-lived sidecar Unix socket path.
    #[must_use]
    pub fn sidecar_socket(&self) -> PathBuf {
        self.root.join(SIDECAR_SOCKET_FILE_NAME)
    }

    /// Return the default persistent enforcement session-state path.
    #[must_use]
    pub fn session_state(&self) -> PathBuf {
        self.root.join(SESSION_STATE_FILE_NAME)
    }

    /// Return the default Authority Ed25519 signing-key path.
    #[must_use]
    pub fn authority_key(&self) -> PathBuf {
        self.root.join(AUTHORITY_KEY_FILE_NAME)
    }

    /// Return the default Authority public verification-key path.
    #[must_use]
    pub fn authority_public_key(&self) -> PathBuf {
        self.root.join(AUTHORITY_PUBLIC_KEY_FILE_NAME)
    }

    /// Return the default audit signing-key path.
    #[must_use]
    pub fn audit_key(&self) -> PathBuf {
        self.root.join(AUDIT_KEY_FILE_NAME)
    }

    /// Return the default revocation-list path.
    #[must_use]
    pub fn revocations(&self) -> PathBuf {
        self.root.join(REVOCATIONS_FILE_NAME)
    }

    /// Return the default directory for the Sidecar's generated HTTPS MITM CA
    /// outside a per-run entry.
    #[must_use]
    pub fn generated_ca_dir(&self) -> PathBuf {
        self.root.join(GENERATED_CA_DIR_NAME)
    }

    /// Return the long-lived Sidecar's MITM CA certificate.
    ///
    /// Public material, like [`RunEntryLayout::ca_cert`]: a wrapped process
    /// cannot verify an intercepted handshake without reading it.
    #[must_use]
    pub fn generated_ca_cert(&self) -> PathBuf {
        self.generated_ca_dir().join(CA_CERT_FILE_NAME)
    }

    /// Return the long-lived Sidecar's MITM CA appended to the host's system
    /// roots.
    ///
    /// Written only under `ca_trust_mode = "append_system_roots"`. Public
    /// material, like [`RuntimeLayout::generated_ca_cert`].
    #[must_use]
    pub fn generated_ca_bundle(&self) -> PathBuf {
        self.generated_ca_dir().join(CA_BUNDLE_FILE_NAME)
    }

    /// Return the long-lived Sidecar's MITM CA private key.
    ///
    /// Secret material, like [`RunEntryLayout::ca_key`]. Never expose this path
    /// to a wrapped process.
    #[must_use]
    pub fn generated_ca_key(&self) -> PathBuf {
        self.generated_ca_dir().join(CA_KEY_FILE_NAME)
    }

    /// Return the directory holding Authority TLS material.
    #[must_use]
    pub fn tls_dir(&self) -> PathBuf {
        self.root.join(TLS_DIR_NAME)
    }

    /// Return the default Authority server TLS certificate path.
    #[must_use]
    pub fn authority_tls_certificate(&self) -> PathBuf {
        self.tls_dir().join(AUTHORITY_TLS_CERTIFICATE_FILE_NAME)
    }

    /// Return the default Authority server TLS private-key path.
    ///
    /// Distinct from [`RuntimeLayout::authority_key`], which is the capability
    /// signing key: same file name, different directory.
    #[must_use]
    pub fn authority_tls_private_key(&self) -> PathBuf {
        self.tls_dir().join(AUTHORITY_TLS_PRIVATE_KEY_FILE_NAME)
    }

    /// Return the default path of the CA certificate a Sidecar verifies the
    /// Authority's TLS identity against.
    #[must_use]
    pub fn authority_tls_ca_certificate(&self) -> PathBuf {
        self.tls_dir().join(AUTHORITY_TLS_CA_CERTIFICATE_FILE_NAME)
    }

    /// Return the default path of the CA private key that issues Authority TLS
    /// certificates.
    #[must_use]
    pub fn authority_tls_ca_private_key(&self) -> PathBuf {
        self.tls_dir().join(AUTHORITY_TLS_CA_PRIVATE_KEY_FILE_NAME)
    }
}

/// Whether the artifact at `path` is anything other than provably absent.
///
/// This is the question every consumer of a state-directory default has to
/// answer before adopting one: `firma config` writes the material, and a
/// deployment that never generated it must keep its "no anchor configured"
/// behavior instead of failing on a file nobody wrote.
///
/// Only a clean `NotFound` counts as absent. A candidate that exists but cannot
/// be stat-ed — a directory mode that hides it, for instance — is reported as
/// present, so the component that opens it reports the real permission error
/// rather than silently degrading. A directory standing where a file belongs is
/// absent: it is not material anyone can read.
///
/// Prefer this over [`Path::is_file`], which folds both of those cases into
/// "absent".
#[must_use]
pub fn is_material_present(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => !metadata.is_dir(),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
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
