//! Shared fixtures for integration tests.

#![allow(clippy::expect_used, clippy::panic, reason = "test fixture setup")]

use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use firma_authority::{AuthorityConfigBuilder, Server};
use firma_config_schema::authority as authority_schema;
use firma_core::{CapabilityClaims, CapabilitySeed};
use firma_identifiers::{AgentId, TokenId};
use firma_test_helpers::bounded::{self, step};
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;
use tonic::transport::Endpoint;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;

const READY_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const STEP_LIMIT: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_millis(50);

/// Observe producer rules after loading the generated configuration boundary.
pub async fn mapping_snapshot(
    config_path: &std::path::Path,
) -> anyhow::Result<firma_protobuf::v1::ActionMappingSnapshot> {
    let root = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config parent"))?;
    let file = firma_config_loader::FirmaConfig::load(config_path)?;
    let mut schema: authority_schema::AuthorityConfig = file.section("authority")?;
    schema.listen_addr = "127.0.0.1:0".into();
    let state = firma_runtime_state::RuntimeLayout::from_root(root.join("state"));
    std::fs::create_dir_all(state.root())?;
    if !state.authority_key().exists() {
        firma_authority::write_keypair(&state.authority_key())?;
    }
    let config = AuthorityConfigBuilder::new(schema, &state)
        .rebase_defaults(root)
        .without_tls()
        .build()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = Server::try_new(config, async {
        let _ = shutdown_rx.await;
    })
    .await?;
    let endpoint = format!("http://127.0.0.1:{}", server.port());
    let task = tokio::spawn(server.run());
    let mut client =
        firma_protobuf::v1::authority_service_client::AuthorityServiceClient::connect(endpoint)
            .await?;
    let mut stream = client
        .watch_policy_bundle(firma_protobuf::v1::WatchPolicyBundleRequest {
            current_version: String::new(),
            credentials: None,
            supported_capabilities: vec![
                firma_protobuf::v1::PolicyBundleCapability::ActionMappingSnapshotV1 as i32,
            ],
        })
        .await?
        .into_inner();
    let mappings = tokio::time::timeout(READY_TIMEOUT, stream.message())
        .await??
        .and_then(|update| update.bundle)
        .and_then(|bundle| bundle.mappings)
        .ok_or_else(|| anyhow::anyhow!("producer mappings missing"))?;
    drop(stream);
    drop(client);
    shutdown_tx
        .send(())
        .map_err(|()| anyhow::anyhow!("producer shutdown receiver closed"))?;
    tokio::time::timeout(SHUTDOWN_TIMEOUT, task).await???;
    Ok(mappings)
}

pub fn agent_id() -> &'static AgentId {
    static AGENT_ID: LazyLock<AgentId> = LazyLock::new(|| {
        "agt_01j0000000e008000000000001"
            .parse()
            .expect("valid test agent ID")
    });
    &AGENT_ID
}

pub fn canonical_seed_toml(raw_token: &str) -> String {
    let issued_at = chrono::Utc::now();
    let claims = CapabilityClaims {
        token_id: TokenId::generate(),
        agent_id: *agent_id(),
        session_id: "sess_test".parse().expect("valid test session ID"),
        action_set: vec!["communication.external.send".to_string()],
        resource_scope: "*".to_string(),
        issued_at,
        expiry: issued_at + chrono::Duration::minutes(15),
        context_hash: "deadbeef".to_string(),
    };
    toml::to_string(&CapabilitySeed::from_claims(&claims, raw_token.to_string()))
        .expect("serialize canonical capability seed")
}

/// Handle to a real Authority running with temporary keys and permit-all policies.
///
/// Start and stop run as bounded [`step`]s, so a stalled Authority fails the
/// test with the step that stalled. Callers run under [`bounded::run`].
pub struct RealAuthority {
    pub url: String,
    pub pub_key_path: PathBuf,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    dir: tempfile::TempDir,
}

impl RealAuthority {
    pub async fn start() -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let policy_dir = dir.path().join("policies");
        let issuance_policy_dir = dir.path().join("issuance-policies");
        std::fs::create_dir(&policy_dir)?;
        std::fs::create_dir(&issuance_policy_dir)?;
        for directory in [&policy_dir, &issuance_policy_dir] {
            std::fs::write(
                directory.join("permit-all.cedar"),
                "permit(principal, action, resource);",
            )?;
        }

        let keypair = AsymmetricKeyPair::<V4>::generate()?;
        let key_path = dir.path().join("authority.key");
        let pub_key_path = dir.path().join("authority.pub");
        std::fs::write(&key_path, keypair.secret.as_bytes())?;
        std::fs::write(&pub_key_path, keypair.public.as_bytes())?;

        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let mappings = dir.path().join("mapping-rules.toml");
        std::fs::write(&mappings, "rules = []\n")?;
        let config = AuthorityConfigBuilder::new(
            authority_schema::AuthorityConfig {
                listen_addr: "127.0.0.1:0".to_string(),
                policy_dir,
                issuance_policy_dir,
                mapping_rules_paths: vec![mappings],
                revocation_file: Some(dir.path().join("revocations.txt")),
                key_file: Some(key_path),
                ..authority_schema::AuthorityConfig::default()
            },
            &firma_runtime_state::RuntimeLayout::from_root(dir.path()),
        )
        .without_tls()
        .build()?;
        let server = Server::try_new(config, async {
            let _ = shutdown_rx.await;
        });
        let server = step("start the Authority", STEP_LIMIT, server).await??;
        let url = format!("http://127.0.0.1:{}", server.port());
        let handle = tokio::spawn(server.run());
        step(
            "wait for the Authority to report SERVING",
            READY_TIMEOUT,
            wait_until_serving(&url),
        )
        .await?;

        Ok(Self {
            url,
            pub_key_path,
            shutdown,
            handle,
            dir,
        })
    }

    pub async fn stop(self) -> anyhow::Result<()> {
        let _ = self.shutdown.send(());
        step("stop the Authority", SHUTDOWN_TIMEOUT, self.handle).await???;
        bounded::remove_dir(self.dir).await
    }
}

async fn wait_until_serving(url: &str) {
    loop {
        if let Ok(endpoint) = Endpoint::from_shared(url.to_string())
            && let Ok(Ok(channel)) = tokio::time::timeout(PROBE_TIMEOUT, endpoint.connect()).await
            && let mut client = HealthClient::new(channel)
            && let Ok(Ok(response)) = tokio::time::timeout(
                PROBE_TIMEOUT,
                client.check(HealthCheckRequest {
                    service: String::new(),
                }),
            )
            .await
            && response.into_inner().status == ServingStatus::Serving as i32
        {
            return;
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}
