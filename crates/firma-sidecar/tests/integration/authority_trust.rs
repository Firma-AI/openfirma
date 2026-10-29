//! Which certificates the Authority channel trusts: the configured CAs alone,
//! any one of them, or the platform's trusted roots when none is configured.
//!
//! The platform roots come from `SSL_CERT_FILE`, so the test runs its checks
//! in a child process of this test binary whose `SSL_CERT_FILE` names a test
//! CA. That makes "trusted by the platform" a certificate this test issued,
//! without changing the environment of the process that runs the other tests.

#![allow(clippy::expect_used, reason = "test code")]

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use firma_config_utils::NonZeroDuration;
use firma_protobuf::v1::IssueCapabilityRequest;
use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_sidecar::authority_client::channel::build_channel;
use firma_sidecar::authority_tls::TlsTrust;
use firma_sidecar::config::AuthorityEndpoint;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CertificateError, Error as TlsError};

/// Set in the child process to the directory holding the test certificates.
const CHILD_DIR: &str = "FIRMA_TEST_AUTHORITY_TRUST_DIR";
const AUTHORITY_HOST: &str = "authority.test";
/// The test the child runs, by its path in this binary.
const TEST: &str =
    "authority_trust::a_configured_ca_is_trusted_alone_and_the_platform_roots_otherwise";

#[test]
fn a_configured_ca_is_trusted_alone_and_the_platform_roots_otherwise() {
    match std::env::var_os(CHILD_DIR) {
        None => run_in_a_child_whose_platform_roots_trust_the_server(),
        Some(dir) => check_trust_sources(Path::new(&dir)),
    }
}

/// Issue a server certificate from one CA, name that CA as the platform roots
/// through `SSL_CERT_FILE`, and run the checks in a child of this binary.
fn run_in_a_child_whose_platform_roots_trust_the_server() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let (platform_ca, platform_issuer) = certificate_authority("Platform CA");
    let (other_ca, other_issuer) = certificate_authority("Unrelated CA");
    let (next_ca, next_issuer) = certificate_authority("Next CA");
    let server_key = KeyPair::generate().expect("server key");
    let server_signed_by = |issuer: &Issuer<'static, KeyPair>| {
        CertificateParams::new(vec![AUTHORITY_HOST.to_owned()])
            .expect("server params")
            .signed_by(&server_key, issuer)
            .expect("server certificate")
            .pem()
    };
    for (name, pem) in [
        ("platform-ca.pem", platform_ca),
        ("other-ca.pem", other_ca),
        ("next-ca.pem", next_ca),
        ("server.pem", server_signed_by(&platform_issuer)),
        ("other-server.pem", server_signed_by(&other_issuer)),
        ("next-server.pem", server_signed_by(&next_issuer)),
        ("server-key.pem", server_key.serialize_pem()),
    ] {
        std::fs::write(dir.path().join(name), pem).expect("write test certificate");
    }

    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", TEST])
        .env(CHILD_DIR, dir.path())
        .env("SSL_CERT_FILE", dir.path().join("platform-ca.pem"))
        .env_remove("SSL_CERT_DIR")
        .output()
        .expect("run the trust checks in a child process");

    assert!(
        output.status.success(),
        "trust checks failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "the child must have run the checks:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn check_trust_sources(dir: &Path) {
    let read = |name: &str| std::fs::read(dir.join(name)).expect("read test certificate");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let (address, handshakes) = serve_tls(&read("server.pem"), &read("server-key.pem")).await;

        assert_eq!(
            certificate_error(address, &[]).await,
            None,
            "with no CA configured, the platform roots must verify the Authority"
        );
        assert_eq!(handshakes.load(Ordering::SeqCst), 1);
        assert_eq!(
            certificate_error(address, &[read("platform-ca.pem")]).await,
            None,
            "the CA that issued the Authority's certificate must verify it"
        );
        assert_eq!(handshakes.load(Ordering::SeqCst), 2);
        assert_eq!(
            certificate_error(address, &[read("other-ca.pem")]).await,
            Some(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            )),
            "a configured CA must replace the platform roots, not add to them"
        );

        // A list: the Authority's certificate may be signed by any listed CA,
        // which is what a CA rotation relies on. No listed CA is in the
        // platform store, so an accepted certificate is one the list verified,
        // and the store stays out of a list too.
        let (other_address, other_handshakes) =
            serve_tls(&read("other-server.pem"), &read("server-key.pem")).await;
        let (next_address, next_handshakes) =
            serve_tls(&read("next-server.pem"), &read("server-key.pem")).await;
        let rotation = [read("other-ca.pem"), read("next-ca.pem")];
        assert_eq!(
            certificate_error(other_address, &rotation).await,
            None,
            "a certificate signed by the first listed CA must be accepted"
        );
        assert_eq!(other_handshakes.load(Ordering::SeqCst), 1);
        assert_eq!(
            certificate_error(next_address, &rotation).await,
            None,
            "a certificate signed by the second listed CA must be accepted"
        );
        assert_eq!(next_handshakes.load(Ordering::SeqCst), 1);
        assert_eq!(
            certificate_error(address, &rotation).await,
            Some(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            )),
            "a configured CA list must replace the platform roots, not add to them"
        );
    });
}

/// A self-signed CA named `name`: its PEM and an issuer that signs with it.
pub fn certificate_authority(name: &str) -> (String, Issuer<'static, KeyPair>) {
    let key = KeyPair::generate().expect("CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let pem = params.self_signed(&key).expect("CA certificate").pem();
    (pem, Issuer::new(params, key))
}

/// Accept TLS connections for `authority.test` on a loopback port, complete
/// the handshake and close. Counts the handshakes that succeeded, so an
/// accepted certificate is observed rather than inferred from a missing error.
async fn serve_tls(cert_pem: &[u8], key_pem: &[u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("server certificate");
    let key = PrivateKeyDer::from_pem_slice(key_pem).expect("server key");
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("server TLS config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("local address");
    let handshakes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handshakes);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            // Count before the stream drops: the client can observe the
            // close, and read the count, as soon as the connection ends.
            if let Ok(tls) = acceptor.accept(stream).await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(tls);
            }
        }
    });
    (address, handshakes)
}

/// The certificate error the client's TLS handshake failed with, if any. Any
/// other outcome means the Authority's certificate was accepted.
async fn certificate_error(address: SocketAddr, ca_pems: &[Vec<u8>]) -> Option<TlsError> {
    let endpoint = AuthorityEndpoint::new(
        &format!("https://{AUTHORITY_HOST}:{}", address.port()),
        Some(address),
    )
    .expect("endpoint");
    let trust = TlsTrust::from_pems(ca_pems);
    let channel = build_channel(
        &endpoint,
        NonZeroDuration::from_static(Duration::from_secs(5)),
        trust,
        None,
    )
    .expect("channel");
    let status = AuthorityServiceClient::new(channel)
        .issue_capability(IssueCapabilityRequest::default())
        .await
        .expect_err("the test server answers no RPC");

    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&status);
    while let Some(error) = source {
        let tls = error.downcast_ref::<TlsError>().or_else(|| {
            error
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::get_ref)
                .and_then(|inner| inner.downcast_ref::<TlsError>())
        });
        if let Some(tls) = tls {
            return Some(tls.clone());
        }
        source = error.source();
    }
    None
}
