//! Shared fixtures for integration tests.

#![allow(clippy::expect_used, clippy::panic, reason = "test fixture setup")]

use std::assert_matches;
use std::net::TcpListener;
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

/// A loopback listener standing in for an Authority that must never be
/// contacted; check it with [`assert_never_contacted`].
pub fn unreached_authority() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    listener
}

pub fn assert_never_contacted(listener: &TcpListener) {
    assert_matches!(
        listener.accept().map(|(_, peer)| peer),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock,
        "the Authority must not have been contacted"
    );
}

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

/// Runtime (enforcement) policy every fixture Authority serves. Issuance is what
/// these tests vary, so the hot-path side stays permissive.
const PERMIT_ALL: &str = "permit(principal, action, resource);";

/// What the Authority's issuance policy set grants.
///
/// A run requests every action class, so the issuance policy is the only thing
/// that decides the grant — including whether there is any grant at all.
#[derive(Clone, Copy)]
pub enum IssuancePolicy {
    /// Only the named action class is authorized, so the granted set is exactly
    /// it however much the run requested.
    PermitOnly(&'static str),
    /// No action class is authorized, so issuance fails closed with
    /// `NO_AUTHORIZED_ACTIONS`.
    ForbidAll,
}

impl IssuancePolicy {
    fn cedar(self) -> String {
        match self {
            Self::PermitOnly(class) => {
                format!("permit(principal, action == Firma::Action::\"{class}\", resource);")
            }
            Self::ForbidAll => "forbid(principal, action, resource);".to_string(),
        }
    }
}

/// Handle to a real Authority running with temporary keys and permit-all
/// runtime policies.
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
    pub async fn start_with(issuance: IssuancePolicy) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let policy_dir = dir.path().join("policies");
        let issuance_policy_dir = dir.path().join("issuance-policies");
        std::fs::create_dir(&policy_dir)?;
        std::fs::create_dir(&issuance_policy_dir)?;
        std::fs::write(policy_dir.join("permit-all.cedar"), PERMIT_ALL)?;
        std::fs::write(issuance_policy_dir.join("issuance.cedar"), issuance.cedar())?;

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

/// Credentials of a Sidecar serving one run with its runtime credential.
pub fn runtime_credentials() -> firma_sidecar::authority_credentials::SidecarCredentialsConfig {
    firma_sidecar::authority_credentials::SidecarCredentialsConfig {
        workspace_id: "ws".to_string(),
        sidecar_id: "sc".to_string(),
        source: firma_sidecar::authority_credentials::CredentialSource::Runtime {
            env: "FIRMA_RUNTIME_CREDENTIAL".to_string(),
            run_id: "run_01j0000000e008000000000001"
                .parse()
                .expect("valid run ID"),
        },
    }
}
