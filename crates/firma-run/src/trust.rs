//! The CA file a wrapped process is told to trust.
//!
//! `firma run` resolves exactly one trust anchor per launch and uses it for
//! two things that must not disagree: the trust environment handed to the
//! wrapped process (`SSL_CERT_FILE` and its ecosystem siblings) and the
//! sandbox filesystem plan, which has to keep that file readable through the
//! control-plane mask. Resolving it twice, from different inputs, is what let
//! a masked certificate reach the agent as a silent fallback to the system
//! roots instead of a launch failure.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use firma_runtime_state::runtime_paths::{CA_CERT_FILE_NAME, CA_DIR_NAME};

use crate::config::CaTrustMode;

/// Common Linux system CA bundle locations, probed in order.
pub const SYSTEM_CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// The single CA file this launch's trust environment names.
///
/// Under [`CaTrustMode::Sole`] this is the Sidecar CA certificate; under
/// [`CaTrustMode::AppendSystemRoots`] it is the generated bundle that carries
/// the host's roots plus that certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarTrustAnchor {
    path: PathBuf,
}

impl SidecarTrustAnchor {
    /// Resolve the anchor for one launch, or `None` when no Sidecar CA is
    /// reachable and the wrapped process keeps the host's own trust store.
    pub fn resolve(
        mode: CaTrustMode,
        network_overrides: &BTreeMap<String, String>,
    ) -> Option<Self> {
        let ca_cert_path = resolve_sidecar_ca_cert_path(network_overrides)?;
        let path = match mode {
            CaTrustMode::AppendSystemRoots => {
                build_appended_ca_bundle(&ca_cert_path).unwrap_or(ca_cert_path)
            }
            CaTrustMode::Sole => ca_cert_path,
        };
        Some(Self { path })
    }

    /// Return the anchor's path as the wrapped process will see it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Point every trust-store environment variable the ecosystems read at
    /// this anchor.
    pub fn inject_trust_env(&self, env: &mut BTreeMap<String, String>) {
        let path = self.path.display().to_string();
        env.insert("FIRMA_SIDECAR_CA_CERT_PATH".to_string(), path.clone());
        // Python / OpenSSL ecosystem.
        env.insert("REQUESTS_CA_BUNDLE".to_string(), path.clone());
        env.insert("SSL_CERT_FILE".to_string(), path.clone());
        env.insert("CURL_CA_BUNDLE".to_string(), path.clone());
        // Node.js ecosystem.
        env.insert("NODE_EXTRA_CA_CERTS".to_string(), path.clone());
        // Git/libcurl callers.
        env.insert("GIT_SSL_CAINFO".to_string(), path);
    }
}

/// Build `firma-ca-bundle.crt` next to `firma_ca_path`, containing the first
/// discovered system root bundle followed by the firma CA. Returns `None`
/// (caller falls back to sole firma-ca) when no system bundle is found or the
/// write fails.
fn build_appended_ca_bundle(firma_ca_path: &Path) -> Option<PathBuf> {
    let roots: Vec<PathBuf> = SYSTEM_CA_BUNDLE_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .collect();
    build_appended_ca_bundle_with_roots(firma_ca_path, &roots)
}

/// Testable core of [`build_appended_ca_bundle`]: takes explicit candidate root
/// paths and concatenates the first existing one with the firma CA.
fn build_appended_ca_bundle_with_roots(firma_ca_path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let system_roots = roots.iter().find(|p| p.is_file())?;
    let mut bundle = match std::fs::read(system_roots) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, path = %system_roots.display(), "failed to read system CA bundle; using sole firma-ca");
            return None;
        }
    };
    let firma_ca = match std::fs::read(firma_ca_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, path = %firma_ca_path.display(), "failed to read firma-ca; using sole firma-ca");
            return None;
        }
    };
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(&firma_ca);
    let bundle_path =
        firma_ca_path.with_file_name(firma_runtime_state::runtime_paths::CA_BUNDLE_FILE_NAME);
    if let Err(error) = std::fs::write(&bundle_path, &bundle) {
        tracing::warn!(%error, path = %bundle_path.display(), "failed to write combined CA bundle; using sole firma-ca");
        return None;
    }
    Some(bundle_path)
}

fn resolve_sidecar_ca_cert_path(network_overrides: &BTreeMap<String, String>) -> Option<PathBuf> {
    if let Some(explicit) = network_overrides.get("FIRMA_SIDECAR_CA_CERT_PATH")
        && !explicit.trim().is_empty()
    {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Some(ca_dir) = network_overrides.get("FIRMA_SIDECAR_CA_DIR")
        && !ca_dir.trim().is_empty()
    {
        let path = PathBuf::from(ca_dir).join(CA_CERT_FILE_NAME);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Ok(explicit) = std::env::var("FIRMA_SIDECAR_CA_CERT_PATH")
        && !explicit.trim().is_empty()
    {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Some(path);
        }
    }

    if let Ok(ca_dir) = std::env::var("FIRMA_SIDECAR_CA_DIR")
        && !ca_dir.trim().is_empty()
    {
        let path = PathBuf::from(ca_dir).join(CA_CERT_FILE_NAME);
        if path.is_file() {
            return Some(path);
        }
    }

    let cwd_candidate = std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join(CA_DIR_NAME).join(CA_CERT_FILE_NAME));
    let default_candidates = [
        cwd_candidate,
        Some(PathBuf::from("/etc/firma/ca").join(CA_CERT_FILE_NAME)),
        Some(PathBuf::from("/var/lib/firma/ca").join(CA_CERT_FILE_NAME)),
    ];

    default_candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::SidecarTrustAnchor;
    use crate::config::CaTrustMode;

    /// Point anchor resolution at `cert` the way an autostarted Sidecar does.
    fn overrides_for(cert: &std::path::Path) -> BTreeMap<String, String> {
        BTreeMap::from([(
            "FIRMA_SIDECAR_CA_CERT_PATH".to_string(),
            cert.display().to_string(),
        )])
    }

    #[test]
    fn appended_ca_bundle_concatenates_system_roots_and_firma_ca() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let system = dir.path().join("system-roots.pem");
        std::fs::write(&system, b"-----SYSTEM ROOT-----\n").unwrap_or_else(|e| panic!("{e}"));
        let firma_ca = dir.path().join("firma-ca.crt");
        std::fs::write(&firma_ca, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));

        let bundle =
            super::build_appended_ca_bundle_with_roots(&firma_ca, std::slice::from_ref(&system))
                .unwrap_or_else(|| panic!("bundle should be built"));
        assert_eq!(bundle, dir.path().join("firma-ca-bundle.crt"));
        let body = std::fs::read_to_string(&bundle).unwrap_or_else(|e| panic!("{e}"));
        assert!(body.contains("SYSTEM ROOT"));
        assert!(body.contains("FIRMA CA"));
    }

    #[test]
    fn appended_ca_bundle_falls_back_when_no_system_roots() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let firma_ca = dir.path().join("firma-ca.crt");
        std::fs::write(&firma_ca, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));
        let missing = dir.path().join("does-not-exist.pem");
        assert!(super::build_appended_ca_bundle_with_roots(&firma_ca, &[missing]).is_none());
    }

    #[test]
    fn injects_every_ecosystem_trust_variable_from_one_anchor() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let cert = dir.path().join("firma-ca.crt");
        std::fs::write(&cert, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));
        let anchor = SidecarTrustAnchor::resolve(CaTrustMode::Sole, &overrides_for(&cert))
            .unwrap_or_else(|| panic!("anchor should resolve"));

        let mut env = BTreeMap::new();
        anchor.inject_trust_env(&mut env);

        let expected = cert.display().to_string();
        assert_eq!(env.get("FIRMA_SIDECAR_CA_CERT_PATH"), Some(&expected));
        assert_eq!(env.get("REQUESTS_CA_BUNDLE"), Some(&expected));
        assert_eq!(env.get("SSL_CERT_FILE"), Some(&expected));
        assert_eq!(env.get("CURL_CA_BUNDLE"), Some(&expected));
        assert_eq!(env.get("NODE_EXTRA_CA_CERTS"), Some(&expected));
        assert_eq!(env.get("GIT_SSL_CAINFO"), Some(&expected));
    }

    /// The anchor is the value the mount planner validates against, so it must
    /// name the file the trust environment actually points at, not the
    /// certificate the bundle was derived from.
    #[test]
    fn append_system_roots_anchors_on_the_generated_bundle() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let cert = dir.path().join("firma-ca.crt");
        std::fs::write(&cert, b"-----FIRMA CA-----\n").unwrap_or_else(|e| panic!("{e}"));

        let anchor =
            SidecarTrustAnchor::resolve(CaTrustMode::AppendSystemRoots, &overrides_for(&cert))
                .unwrap_or_else(|| panic!("anchor should resolve"));

        let system_roots_present = super::SYSTEM_CA_BUNDLE_CANDIDATES
            .iter()
            .any(|candidate| std::path::Path::new(candidate).is_file());
        if system_roots_present {
            assert_eq!(anchor.path(), dir.path().join("firma-ca-bundle.crt"));
        } else {
            // Without host roots to append there is nothing to build, and the
            // anchor falls back to the bare certificate.
            assert_eq!(anchor.path(), cert);
        }
    }
}
