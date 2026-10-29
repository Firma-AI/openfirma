//! TLS material for the Sidecar's connections to the Authority and to the
//! Authority's own audit service.
//!
//! The files `[sidecar.authority]` names are read once at startup, so both
//! connections trust the same CAs and present the same client identity.

use std::path::{Path, PathBuf};

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

use crate::config::{AuthorityConfig, AuthorityTrust};

/// The Authority's TLS material, read from the files the configuration names.
#[derive(Debug)]
pub struct AuthorityTls {
    /// The configured CA certificate PEMs; empty for the platform store.
    ca_certs: Vec<Vec<u8>>,
    client_identity: Option<ClientIdentity>,
}

/// What a TLS client verifies the server's certificate against.
#[derive(Debug, Clone, Copy)]
pub enum TlsTrust<'a> {
    /// Only these CA certificate PEMs; never empty.
    Cas(&'a [Vec<u8>]),
    /// The platform's trusted roots.
    PlatformStore,
}

/// An mTLS client certificate and its key, both PEM.
struct ClientIdentity {
    cert: Vec<u8>,
    key: Vec<u8>,
}

impl std::fmt::Debug for ClientIdentity {
    /// Never prints the private key.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientIdentity")
            .finish_non_exhaustive()
    }
}

/// Error reading the Authority's TLS material.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityTlsError {
    /// A configured file could not be read.
    #[error("failed to read {what} {}", path.display())]
    Read {
        /// What the file holds.
        what: &'static str,
        /// The configured path.
        path: PathBuf,
        /// The read error.
        #[source]
        source: std::io::Error,
    },
    /// A configured CA file is not PEM.
    #[error("failed to parse authority CA cert {}", path.display())]
    ParseCaCert {
        /// The configured path.
        path: PathBuf,
        /// The parse error.
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    /// A configured CA file holds no certificate, so it would anchor nothing.
    #[error("authority CA cert {} holds no CERTIFICATE PEM block", path.display())]
    EmptyCaCert {
        /// The configured path.
        path: PathBuf,
    },
    /// Only one of the mTLS client certificate and key is configured.
    #[error("tls_client_cert and tls_client_key must both be set or both unset")]
    PartialClientIdentity,
}

/// Read the CA certificate PEMs `trust` names, in order.
///
/// # Errors
///
/// Returns [`AuthorityTlsError`] naming the file that could not be read, is
/// not PEM, or holds no certificate: a readable file that anchors nothing
/// would otherwise fail only at the handshake it was meant to secure.
pub fn read_ca_pems(trust: &AuthorityTrust) -> Result<Vec<Vec<u8>>, AuthorityTlsError> {
    trust
        .ca_cert_paths()
        .iter()
        .map(|path| {
            let pem = read(path, "authority CA cert")?;
            let certificates = CertificateDer::pem_slice_iter(&pem)
                .try_fold(0_usize, |count, certificate| certificate.map(|_| count + 1))
                .map_err(|source| AuthorityTlsError::ParseCaCert {
                    path: path.clone(),
                    source,
                })?;
            if certificates == 0 {
                return Err(AuthorityTlsError::EmptyCaCert { path: path.clone() });
            }
            Ok(pem)
        })
        .collect()
}

impl AuthorityTls {
    /// Read every file the configuration names.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityTlsError`] naming the file that could not be read,
    /// or when only half of the client identity is configured.
    pub fn read(config: &AuthorityConfig) -> Result<Self, AuthorityTlsError> {
        let ca_certs = read_ca_pems(&config.trust)?;
        let cert = config
            .tls_client_cert_path
            .as_deref()
            .map(|path| read(path, "mTLS client cert"))
            .transpose()?;
        let key = config
            .tls_client_key_path
            .as_deref()
            .map(|path| read(path, "mTLS client key"))
            .transpose()?;
        let client_identity = match (cert, key) {
            (Some(cert), Some(key)) => Some(ClientIdentity { cert, key }),
            (None, None) => None,
            _ => return Err(AuthorityTlsError::PartialClientIdentity),
        };
        Ok(Self {
            ca_certs,
            client_identity,
        })
    }

    /// What the Authority's certificate is verified against: the configured
    /// CAs alone when any, otherwise the platform's roots.
    #[must_use]
    pub(crate) fn trust(&self) -> TlsTrust<'_> {
        TlsTrust::from_pems(&self.ca_certs)
    }

    /// The mTLS client certificate and key PEMs, if any.
    #[must_use]
    pub(crate) fn client_identity(&self) -> Option<(&[u8], &[u8])> {
        self.client_identity
            .as_ref()
            .map(|identity| (identity.cert.as_slice(), identity.key.as_slice()))
    }

    /// The TLS settings for an `https` connection to the Authority.
    #[must_use]
    pub(crate) fn client_config(&self) -> ClientTlsConfig {
        client_tls_config(self.trust(), self.client_identity())
    }
}

impl<'a> TlsTrust<'a> {
    /// The configured CAs alone when any, otherwise the platform's roots.
    #[must_use]
    pub fn from_pems(pems: &'a [Vec<u8>]) -> Self {
        if pems.is_empty() {
            Self::PlatformStore
        } else {
            Self::Cas(pems)
        }
    }
}

fn read(path: &Path, what: &'static str) -> Result<Vec<u8>, AuthorityTlsError> {
    std::fs::read(path).map_err(|source| AuthorityTlsError::Read {
        what,
        path: path.to_path_buf(),
        source,
    })
}

/// The TLS settings for an `https` connection: the `trust` source, and the
/// mTLS client identity as a `(cert, key)` PEM pair when set.
///
/// [`TlsTrust::Cas`] trusts those CAs alone; [`TlsTrust::PlatformStore`] the
/// platform's trusted roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` override them).
pub(crate) fn client_tls_config(
    trust: TlsTrust<'_>,
    identity: Option<(&[u8], &[u8])>,
) -> ClientTlsConfig {
    // Tonic cannot infer its provider if a workspace member also enables
    // AWS-LC. Keep OpenFirma's Ring default, or the embedder's prior choice.
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Exactly one trust source: tonic adds the platform roots to pinned CAs
    // instead of replacing them, so they must never be enabled together.
    let tls = match trust {
        TlsTrust::PlatformStore => ClientTlsConfig::new().with_native_roots(),
        TlsTrust::Cas(pems) => {
            ClientTlsConfig::new().ca_certificates(pems.iter().map(Certificate::from_pem))
        }
    };
    match identity {
        Some((cert, key)) => tls.identity(Identity::from_pem(cert, key)),
        None => tls,
    }
}
