use firma_proto::firma::v1::IssueCapabilityRequest;
use firma_proto::firma::v1::authority_service_client::AuthorityServiceClient;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tempfile::TempDir;
use tokio::sync::oneshot;

use firma_authority::{AuthorityConfig, Server};

struct TestServer {
    addr: String,
    _temp_dir: TempDir,
    shutdown_tx: oneshot::Sender<()>,
}

impl TestServer {
    async fn start() -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let policy_dir = temp_dir.path().join("policies");
        std::fs::create_dir(&policy_dir).expect("failed to create policy dir");

        // Add a permit-all policy
        std::fs::write(
            policy_dir.join("permit_all.cedar"),
            "permit(principal, action, resource);",
        )
        .expect("failed to write policy");

        let revocation_file = temp_dir.path().join("revocations.txt");
        std::fs::write(&revocation_file, "").expect("failed to create revocation file");

        let key_file = temp_dir.path().join("authority.key");

        // Generate a real Ed25519 key for the test
        let kp = AsymmetricKeyPair::<V4>::generate().expect("failed to generate key");
        std::fs::write(&key_file, kp.secret.as_bytes()).expect("failed to write key");

        // Bind to port 0 for random port assignment
        let config = AuthorityConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            policy_dir,
            revocation_file,
            key_file,
            max_ttl_seconds: 3600,
            log_level: "info".to_string(),
            bundle_ttl_seconds: 30,
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
            _temp_dir: temp_dir,
            shutdown_tx,
        }
    }

    fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[tokio::test]
async fn test_issue_capability_e2e() {
    let server = TestServer::start().await;

    // Connect to the server
    let mut client = AuthorityServiceClient::connect(server.addr.clone())
        .await
        .expect("failed to connect to server");

    let request = IssueCapabilityRequest {
        agent_id: "test_agent".to_string(),
        requested_actions: vec!["http.get".to_string()],
        resource_scope: "*".to_string(),
        session_id: "test_session".to_string(),
        requested_ttl_seconds: 300,
    };

    let response = client.issue_capability(request).await.expect("RPC failed");
    let inner = response.into_inner();

    assert!(inner.granted);
    let token = inner.token.expect("token missing");
    assert_eq!(token.agent_id, "test_agent");
    assert!(!token.signature.is_empty());

    server.stop();
}
