//! mTLS allow-list client certificate verifier.
//!
//! Wraps `WebPkiClientVerifier` (standard chain validation) with a CN/SAN
//! allow-list check. Clients whose certificate chain is invalid OR whose
//! identity is not in the allow-list are rejected **at the TLS handshake
//! level** — no gRPC frame is ever received from them.
//!
//! # Identity extraction
//!
//! The identity checked against the allow-list is, in order of preference:
//! 1. The first DNS SAN in the Subject Alternative Name extension.
//! 2. The Common Name (CN) from the Subject Distinguished Name.
//!
//! At least one of these must appear in the authorized-clients list for the
//! handshake to succeed.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

use crate::authorized_clients::AuthorizedClientSet;

/// A [`ClientCertVerifier`] that delegates chain validation to an inner
/// `WebPkiClientVerifier` and additionally requires the client CN or DNS SAN
/// to appear in an [`AuthorizedClientSet`].
///
/// Rejects at handshake time with `rustls::Error::General` so the TCP
/// connection is closed before any gRPC traffic flows.
#[derive(Debug)]
pub struct AllowListClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow_list: Arc<AuthorizedClientSet>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl AllowListClientVerifier {
    /// Create a new verifier.
    ///
    /// * `inner` — Standard PKI verifier (e.g. from `WebPkiClientVerifier::builder_with_provider`).
    /// * `allow_list` — Set of authorized identities; shared with the server for logging.
    pub fn new(
        inner: Arc<dyn ClientCertVerifier>,
        allow_list: Arc<AuthorizedClientSet>,
        supported_algs: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            inner,
            allow_list,
            supported_algs,
        }
    }
}

impl ClientCertVerifier for AllowListClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // Step 1: standard PKI chain validation via WebPkiClientVerifier.
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // Step 2: extract identity from the client certificate.
        let identity = extract_identity(end_entity).ok_or_else(|| {
            tracing::warn!("mTLS client cert has no extractable CN or DNS SAN — rejecting");
            TlsError::General(
                "client certificate contains no recognisable identity (CN or DNS SAN)".into(),
            )
        })?;

        // Step 3: check against the allow-list.
        if self.allow_list.contains(&identity) {
            tracing::debug!(identity = %identity, "mTLS client cert authorized");
            Ok(ClientCertVerified::assertion())
        } else {
            tracing::warn!(
                identity = %identity,
                "mTLS client cert identity not in authorized-clients list — rejecting at handshake"
            );
            Err(TlsError::General(format!(
                "client identity '{identity}' is not in the authorized-clients list"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Certificate identity extraction
// ---------------------------------------------------------------------------

/// Extract the primary identity string from a DER-encoded certificate.
///
/// Tries DNS SANs first, then falls back to the Subject CN. Returns `None`
/// if neither is present.
fn extract_identity(cert_der: &CertificateDer<'_>) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, parsed) = X509Certificate::from_der(cert_der.as_ref()).ok()?;

    // Prefer the first DNS SAN.
    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns) = name {
                    return Some((*dns).to_string());
                }
            }
        }
    }

    // Fall back to Subject CN.
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    fn make_allow_list(ids: &[&str]) -> Arc<AuthorizedClientSet> {
        // Build via TOML round-trip to avoid exposing internal constructor.
        use std::io::Write as _;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        for id in ids {
            writeln!(f, "[[authorized]]\ncn = \"{id}\"").unwrap();
        }
        Arc::new(AuthorizedClientSet::load(f.path()).unwrap())
    }

    fn generate_client_cert(cn: &str, san_dns: Option<&str>) -> rcgen::CertifiedKey {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        ca_params.distinguished_name = dn;
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        client_params.distinguished_name = dn;
        if let Some(dns) = san_dns {
            client_params.subject_alt_names = vec![SanType::DnsName(dns.try_into().unwrap())];
        }
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();
        rcgen::CertifiedKey {
            cert: client_cert,
            key_pair: client_key,
        }
    }

    #[test]
    fn extract_identity_prefers_san_over_cn() {
        let ck = generate_client_cert("cn-value", Some("san.example.com"));
        let der = CertificateDer::from(ck.cert.der().to_vec());
        let identity = extract_identity(&der);
        assert_eq!(identity.as_deref(), Some("san.example.com"));
    }

    #[test]
    fn extract_identity_falls_back_to_cn() {
        let ck = generate_client_cert("cn-only.example.com", None);
        let der = CertificateDer::from(ck.cert.der().to_vec());
        let identity = extract_identity(&der);
        assert_eq!(identity.as_deref(), Some("cn-only.example.com"));
    }

    #[test]
    fn authorized_client_set_lookup() {
        let set = make_allow_list(&["allowed-sidecar", "other-sidecar"]);
        assert!(set.contains("allowed-sidecar"));
        assert!(!set.contains("unauthorized"));
        assert_eq!(set.len(), 2);
    }

    // Note: full mTLS handshake-level rejection is covered by the integration
    // tests in tests/e2e_mtls.rs.
}
