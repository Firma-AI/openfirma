#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::path::PathBuf;

use firma_protobuf::v1::authority_service_client::AuthorityServiceClient;
use firma_protobuf::v1::{
    IssueCapabilityRequest, WatchPolicyBundleRequest, WatchRevocationsRequest,
};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use prost_types::Timestamp;
use tempfile::TempDir;
use tokio::sync::oneshot;

use firma_authority::{AuthorityConfig, AuthorityTlsConfig, Server};

struct TestServer {
    addr: String,
    policy_dir: PathBuf,
    revocation_file: PathBuf,
    _temp_dir: TempDir,
    shutdown_tx: oneshot::Sender<()>,
}

impl TestServer {
    async fn start() -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let policy_dir = temp_dir.path().join("policies");
        std::fs::create_dir(&policy_dir).expect("failed to create policy dir");

        std::fs::write(
            policy_dir.join("permit_all.cedar"),
            "permit(principal, action, resource);",
        )
        .expect("failed to write policy");

        let issuance_policy_dir = temp_dir.path().join("issuance-policies");
        std::fs::create_dir(&issuance_policy_dir).expect("failed to create issuance policy dir");
        std::fs::write(
            issuance_policy_dir.join("permit_all.cedar"),
            "permit(principal, action, resource);",
        )
        .expect("failed to write issuance policy");

        let revocation_file = temp_dir.path().join("revocations.txt");

        let key_file = temp_dir.path().join("authority.key");
        let kp = AsymmetricKeyPair::<V4>::generate().expect("failed to generate key");
        std::fs::write(&key_file, kp.secret.as_bytes()).expect("failed to write key");

        let config = AuthorityConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            policy_dir: policy_dir.clone(),
            issuance_policy_dir: issuance_policy_dir.clone(),
            schema_path: None,
            revocation_file: revocation_file.clone(),
            key_file,
            max_ttl_seconds: 3600,
            log_level: "info".to_string(),
            bundle_ttl_seconds: 30,
            tls: AuthorityTlsConfig::default(),
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown_signal = async {
            let _ = shutdown_rx.await;
        };

        let server = Server::try_new(config, shutdown_signal)
            .await
            .expect("failed to create server");
        let port = server.port();
        let addr_str = format!("http://127.0.0.1:{port}");

        tokio::spawn(async move {
            server.run().await.expect("server failed");
        });

        Self {
            addr: addr_str,
            policy_dir,
            revocation_file,
            _temp_dir: temp_dir,
            shutdown_tx,
        }
    }

    fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[tokio::test]
async fn issue_capability_e2e() {
    let server = TestServer::start().await;

    // Connect to the server
    let mut client = AuthorityServiceClient::connect(server.addr.clone())
        .await
        .expect("failed to connect to server");

    let request = IssueCapabilityRequest {
        agent_id: "agt_01j0000000e008000000000001".to_string(),
        requested_actions: vec!["filesystem.read".to_string()],
        resource_scope: "*".to_string(),
        session_id: "test_session".to_string(),
        requested_ttl_seconds: 300,
        credentials: None,
    };

    let response = client.issue_capability(request).await.expect("RPC failed");
    let inner = response.into_inner();

    assert!(inner.granted);
    let token = inner.token.expect("token missing");
    assert_eq!(token.agent_id, "agt_01j0000000e008000000000001");
    assert!(!token.signature.is_empty());

    server.stop();
}

#[tokio::test]
async fn watch_policy_bundle_streams_on_connect() {
    let server = TestServer::start().await;

    let mut client = AuthorityServiceClient::connect(server.addr.clone())
        .await
        .expect("failed to connect");

    let mut stream = client
        .watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
            credentials: None,
        })
        .await
        .expect("RPC failed")
        .into_inner();

    let update = tokio::time::timeout(tokio::time::Duration::from_millis(500), stream.message())
        .await
        .expect("timed out waiting for initial bundle")
        .expect("stream error")
        .expect("stream ended");

    let bundle = update.bundle.expect("bundle missing");
    assert!(!bundle.version.is_empty());
    assert_eq!(bundle.ttl_seconds, 30);

    server.stop();
}

#[tokio::test]
async fn watch_policy_bundle_pushes_on_file_change() {
    let server = TestServer::start().await;

    let mut client = AuthorityServiceClient::connect(server.addr.clone())
        .await
        .expect("failed to connect");

    let mut stream = client
        .watch_policy_bundle(WatchPolicyBundleRequest {
            current_version: String::new(),
            credentials: None,
        })
        .await
        .expect("RPC failed")
        .into_inner();

    let initial = tokio::time::timeout(tokio::time::Duration::from_millis(500), stream.message())
        .await
        .expect("timed out waiting for initial bundle")
        .expect("stream error")
        .expect("stream ended");
    let v1 = initial.bundle.expect("bundle missing").version;

    std::fs::write(
        server.policy_dir.join("permit_all.cedar"),
        "forbid(principal, action, resource);",
    )
    .expect("failed to overwrite policy");

    let update = tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.message())
        .await
        .expect("timed out waiting for bundle update")
        .expect("stream error")
        .expect("stream ended");
    let v2 = update.bundle.expect("bundle missing").version;

    assert_ne!(v1, v2);

    server.stop();
}

#[tokio::test]
async fn watch_revocations_streams_new_events() {
    let server = TestServer::start().await;

    let mut client = AuthorityServiceClient::connect(server.addr.clone())
        .await
        .expect("failed to connect");

    let mut stream = client
        .watch_revocations(WatchRevocationsRequest {
            since: None,
            credentials: None,
        })
        .await
        .expect("RPC failed")
        .into_inner();

    let token_id = firma_core::token::TokenId::new();
    std::fs::write(&server.revocation_file, format!("{token_id}\n"))
        .expect("failed to write revocation");

    let event = tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.message())
        .await
        .expect("timed out waiting for revocation event")
        .expect("stream error")
        .expect("stream ended");

    assert_eq!(event.token_id, token_id.to_string());

    server.stop();
}

#[tokio::test]
async fn watch_revocations_fails_on_invalid_timestamp() {
    let server = TestServer::start().await;

    let mut client = AuthorityServiceClient::connect(server.addr.clone())
        .await
        .expect("failed to connect");

    let error = client
        .watch_revocations(WatchRevocationsRequest {
            since: Some(Timestamp {
                seconds: 1_783_676_609,
                nanos: -123,
            }),
            credentials: None,
        })
        .await
        .unwrap_err();

    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "invalid timestamp for `since`");
}
