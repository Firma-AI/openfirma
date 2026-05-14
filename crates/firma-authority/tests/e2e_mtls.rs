//! mTLS integration tests for the Authority server.
//!
//! Verifies that:
//! 1. An allow-listed Sidecar can connect and receive policy bundles.
//! 2. A non-allow-listed Sidecar is rejected at the TLS handshake.
//! 3. A Sidecar presenting no client certificate is rejected at the TLS handshake.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::io::Write as _;

use firma_authority::{AuthorityConfig, Server};
use firma_proto::firma::v1::WatchPolicyBundleRequest;
use firma_proto::firma::v1::authority_service_client::AuthorityServiceClient;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

// ---------------------------------------------------------------------------
// TLS certificate helpers
// ---------------------------------------------------------------------------

struct MtlsCerts {
    /// Authority server CA cert (PEM) — used to sign the server cert.
    server_ca_cert_pem: Vec<u8>,
    /// Authority server cert (PEM).
    server_cert_pem: Vec<u8>,
    /// Authority server key (PEM).
    server_key_pem: Vec<u8>,
    /// Client CA cert (PEM) — distributes to Authority for client verification.
    client_ca_cert_pem: Vec<u8>,
    /// Client CA key (PEM) — used to sign sidecar client certs.
    client_ca_key_pem: Vec<u8>,
}

fn generate_mtls_certs() -> MtlsCerts {
    // Server CA
    let server_ca_key = KeyPair::generate().unwrap();
    let mut server_ca_params = CertificateParams::default();
    server_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Test Server CA");
    server_ca_params.distinguished_name = dn;
    let server_ca_cert = server_ca_params.self_signed(&server_ca_key).unwrap();

    // Server cert
    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &server_ca_cert, &server_ca_key)
        .unwrap();

    // Client CA
    let client_ca_key = KeyPair::generate().unwrap();
    let mut client_ca_params = CertificateParams::default();
    client_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Test Client CA");
    client_ca_params.distinguished_name = dn;
    let client_ca_cert = client_ca_params.self_signed(&client_ca_key).unwrap();

    MtlsCerts {
        server_ca_cert_pem: server_ca_cert.pem().into_bytes(),
        server_cert_pem: server_cert.pem().into_bytes(),
        server_key_pem: server_key.serialize_pem().into_bytes(),
        client_ca_cert_pem: client_ca_cert.pem().into_bytes(),
        client_ca_key_pem: client_ca_key.serialize_pem().into_bytes(),
    }
}

/// Generate a client certificate signed by the given CA cert/key PEM.
struct ClientCert {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    /// The identity that was embedded (SAN if set, else CN).
    identity: String,
}

fn generate_client_cert(
    cn: &str,
    san: Option<&str>,
    ca_cert_pem: &[u8],
    ca_key_pem: &[u8],
) -> ClientCert {
    let ca_key_str = std::str::from_utf8(ca_key_pem).unwrap();
    let ca_cert_str = std::str::from_utf8(ca_cert_pem).unwrap();

    let ca_key = KeyPair::from_pem(ca_key_str).unwrap();
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_str).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::default();
    client_params.is_ca = IsCa::NoCa;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    client_params.distinguished_name = dn;
    if let Some(s) = san {
        client_params.subject_alt_names = vec![SanType::DnsName(s.try_into().unwrap())];
    }

    let cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    ClientCert {
        cert_pem: cert.pem().into_bytes(),
        key_pem: client_key.serialize_pem().into_bytes(),
        identity: san.unwrap_or(cn).to_string(),
    }
}

// ---------------------------------------------------------------------------
// Test server helper
// ---------------------------------------------------------------------------

struct MtlsTestServer {
    port: u16,
    _temp_dir: TempDir,
    shutdown_tx: oneshot::Sender<()>,
}

impl MtlsTestServer {
    /// Start an mTLS Authority with the given certs and allow-list.
    async fn start(certs: &MtlsCerts, allowed_identities: &[&str]) -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");

        // Write cert files.
        let server_cert_path = temp_dir.path().join("server.crt");
        let server_key_path = temp_dir.path().join("server.key");
        let client_ca_cert_path = temp_dir.path().join("client-ca.crt");
        let authorized_clients_path = temp_dir.path().join("authorized_clients.toml");

        std::fs::write(&server_cert_path, &certs.server_cert_pem).unwrap();
        std::fs::write(&server_key_path, &certs.server_key_pem).unwrap();
        std::fs::write(&client_ca_cert_path, &certs.client_ca_cert_pem).unwrap();

        // Write authorized clients TOML.
        let mut f = std::fs::File::create(&authorized_clients_path).unwrap();
        for id in allowed_identities {
            writeln!(f, "[[authorized]]\ncn = \"{id}\"").unwrap();
        }

        // Set up policy dirs.
        let policy_dir = temp_dir.path().join("policies");
        std::fs::create_dir(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("permit.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();

        let issuance_dir = temp_dir.path().join("issuance-policies");
        std::fs::create_dir(&issuance_dir).unwrap();
        std::fs::write(
            issuance_dir.join("permit.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();

        let revocation_file = temp_dir.path().join("revocations.txt");
        let key_file = temp_dir.path().join("authority.key");
        let kp = AsymmetricKeyPair::<V4>::generate().unwrap();
        std::fs::write(&key_file, kp.secret.as_bytes()).unwrap();

        let config = AuthorityConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            policy_dir,
            issuance_policy_dir: issuance_dir,
            schema_path: None,
            revocation_file,
            key_file,
            max_ttl_seconds: 3600,
            log_level: "info".to_string(),
            bundle_ttl_seconds: 30,
            tls_cert_path: Some(server_cert_path),
            tls_key_path: Some(server_key_path),
            mtls_client_ca_cert_path: Some(client_ca_cert_path),
            mtls_client_ca_key_path: None,
            authorized_clients_path: Some(authorized_clients_path),
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown_signal = async {
            let _ = shutdown_rx.await;
        };

        let server = Server::try_new(config, shutdown_signal)
            .await
            .expect("failed to create mTLS server");
        let port = server.port();

        tokio::spawn(async move {
            server.run().await.expect("server failed");
        });

        // Brief delay for the server to become ready.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        MtlsTestServer {
            port,
            _temp_dir: temp_dir,
            shutdown_tx,
        }
    }

    fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }

    fn url(&self) -> String {
        format!("https://localhost:{}", self.port)
    }
}

/// Build a gRPC channel with mTLS client identity to the test server.
fn build_mtls_channel(
    url: &str,
    server_ca_cert_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> anyhow::Result<Channel> {
    let ca_cert = Certificate::from_pem(server_ca_cert_pem);
    let identity = Identity::from_pem(client_cert_pem, client_key_pem);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity);
    let channel = Endpoint::from_shared(url.to_string())?
        .connect_timeout(std::time::Duration::from_secs(3))
        .tls_config(tls)?
        .connect_lazy();
    Ok(channel)
}

/// Build a TLS-only channel (no client cert) to the test server.
fn build_tls_only_channel(url: &str, server_ca_cert_pem: &[u8]) -> anyhow::Result<Channel> {
    let ca_cert = Certificate::from_pem(server_ca_cert_pem);
    let tls = ClientTlsConfig::new().ca_certificate(ca_cert);
    let channel = Endpoint::from_shared(url.to_string())?
        .connect_timeout(std::time::Duration::from_secs(3))
        .tls_config(tls)?
        .connect_lazy();
    Ok(channel)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// An allow-listed Sidecar with a valid client cert can connect and receives
/// the initial policy bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_allow_listed_client_receives_policy_bundle() {
    let certs = generate_mtls_certs();
    let client = generate_client_cert(
        "sidecar-allowed",
        Some("sidecar-allowed.internal"),
        &certs.client_ca_cert_pem,
        &certs.client_ca_key_pem,
    );

    let server = MtlsTestServer::start(&certs, &[&client.identity]).await;
    let channel = build_mtls_channel(
        &server.url(),
        &certs.server_ca_cert_pem,
        &client.cert_pem,
        &client.key_pem,
    )
    .expect("failed to build mTLS channel");

    let mut grpc = AuthorityServiceClient::new(channel);
    let stream_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        grpc.watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
        }),
    )
    .await
    .expect("timed out waiting for WatchPolicyBundle RPC");

    assert!(
        stream_result.is_ok(),
        "allow-listed client should receive policy bundle stream, got: {stream_result:?}"
    );

    let mut stream = stream_result.unwrap().into_inner();
    let msg = tokio::time::timeout(tokio::time::Duration::from_secs(3), stream.message())
        .await
        .expect("timed out waiting for first bundle message");

    assert!(
        msg.is_ok(),
        "expected a policy bundle update from allow-listed client"
    );

    server.stop();
}

/// A Sidecar whose client cert CN/SAN is NOT in the allow-list is rejected
/// at the TLS handshake level before any gRPC traffic flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_non_allow_listed_client_rejected_at_handshake() {
    let certs = generate_mtls_certs();
    // Server allows "authorized-sidecar" only.
    let server = MtlsTestServer::start(&certs, &["authorized-sidecar"]).await;

    // Client presents "unauthorized-sidecar" identity.
    let client = generate_client_cert(
        "unauthorized-sidecar",
        None,
        &certs.client_ca_cert_pem,
        &certs.client_ca_key_pem,
    );

    let channel = build_mtls_channel(
        &server.url(),
        &certs.server_ca_cert_pem,
        &client.cert_pem,
        &client.key_pem,
    )
    .expect("failed to build mTLS channel");

    let mut grpc = AuthorityServiceClient::new(channel);
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        grpc.watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
        }),
    )
    .await
    .expect("timed out")
    .err();

    assert!(
        result.is_some(),
        "non-allow-listed client must be rejected; got Ok (should have failed)"
    );
}

/// A Sidecar that presents NO client certificate is rejected at the TLS
/// handshake because `client_auth_mandatory()` returns `true`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_missing_client_cert_rejected_at_handshake() {
    let certs = generate_mtls_certs();
    let server = MtlsTestServer::start(&certs, &["authorized-sidecar"]).await;

    // Build a channel WITHOUT client identity — only the server CA cert.
    let channel = build_tls_only_channel(&server.url(), &certs.server_ca_cert_pem)
        .expect("failed to build TLS-only channel");

    let mut grpc = AuthorityServiceClient::new(channel);
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        grpc.watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
        }),
    )
    .await
    .expect("timed out")
    .err();

    assert!(
        result.is_some(),
        "client without cert must be rejected; got Ok (should have failed)"
    );

    server.stop();
}

/// With a CN-based identity (no SAN), the CN is matched against the allow-list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_cn_identity_matched_when_no_san() {
    let certs = generate_mtls_certs();
    let client = generate_client_cert(
        "cn-only-sidecar",
        None, // No SAN — CN is the identity
        &certs.client_ca_cert_pem,
        &certs.client_ca_key_pem,
    );

    let server = MtlsTestServer::start(&certs, &["cn-only-sidecar"]).await;

    let channel = build_mtls_channel(
        &server.url(),
        &certs.server_ca_cert_pem,
        &client.cert_pem,
        &client.key_pem,
    )
    .expect("failed to build mTLS channel");

    let mut grpc = AuthorityServiceClient::new(channel);
    let stream_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        grpc.watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
        }),
    )
    .await
    .expect("timed out");

    assert!(
        stream_result.is_ok(),
        "CN-matched allow-listed client should connect; got: {stream_result:?}"
    );

    server.stop();
}

/// A valid client cert signed by the WRONG CA is rejected (chain validation
/// fails before the allow-list check).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_wrong_client_ca_rejected_at_handshake() {
    let certs = generate_mtls_certs();

    // A separate, unrecognized CA.
    let rogue_ca_key = KeyPair::generate().unwrap();
    let mut rogue_ca_params = CertificateParams::default();
    rogue_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Rogue CA");
    rogue_ca_params.distinguished_name = dn;
    let rogue_ca_cert = rogue_ca_params.self_signed(&rogue_ca_key).unwrap();

    let rogue_ca_cert_pem = rogue_ca_cert.pem().into_bytes();
    let rogue_ca_key_pem = rogue_ca_key.serialize_pem().into_bytes();

    // Client cert signed by rogue CA, CN in the allow-list.
    let client = generate_client_cert(
        "authorized-sidecar",
        None,
        &rogue_ca_cert_pem,
        &rogue_ca_key_pem,
    );

    // Server trusts the original client CA, not the rogue one.
    let server = MtlsTestServer::start(&certs, &["authorized-sidecar"]).await;

    let channel = build_mtls_channel(
        &server.url(),
        &certs.server_ca_cert_pem,
        &client.cert_pem,
        &client.key_pem,
    )
    .expect("failed to build mTLS channel");

    let mut grpc = AuthorityServiceClient::new(channel);
    let result = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        grpc.watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
        }),
    )
    .await
    .expect("timed out")
    .err();

    assert!(
        result.is_some(),
        "cert signed by rogue CA must be rejected; got Ok (should have failed)"
    );

    server.stop();
}
