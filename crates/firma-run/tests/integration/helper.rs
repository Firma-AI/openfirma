//! Shared fixtures for integration tests.

#![allow(clippy::expect_used, reason = "test fixture setup")]

use std::path::PathBuf;
use std::sync::LazyLock;

use firma_authority::{AuthorityConfigBuilder, Server};
use firma_config_schema::authority as authority_schema;
use firma_identifiers::AgentId;
use pasetors::keys::{AsymmetricKeyPair, Generate};
use pasetors::version4::V4;

pub fn agent_id() -> &'static AgentId {
    static AGENT_ID: LazyLock<AgentId> = LazyLock::new(|| {
        "agt_01j0000000e008000000000001"
            .parse()
            .expect("valid test agent ID")
    });
    &AGENT_ID
}

/// Handle to a real Authority running with temporary keys and permit-all policies.
pub struct RealAuthority {
    pub url: String,
    pub pub_key_path: PathBuf,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    _dir: tempfile::TempDir,
}

impl RealAuthority {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_dir = dir.path().join("policies");
        let issuance_policy_dir = dir.path().join("issuance-policies");
        std::fs::create_dir(&policy_dir).expect("create policy dir");
        std::fs::create_dir(&issuance_policy_dir).expect("create issuance policy dir");
        for directory in [&policy_dir, &issuance_policy_dir] {
            std::fs::write(
                directory.join("permit-all.cedar"),
                "permit(principal, action, resource);",
            )
            .expect("write policy");
        }

        let keypair = AsymmetricKeyPair::<V4>::generate().expect("keypair");
        let key_path = dir.path().join("authority.key");
        let pub_key_path = dir.path().join("authority.pub");
        std::fs::write(&key_path, keypair.secret.as_bytes()).expect("write secret key");
        std::fs::write(&pub_key_path, keypair.public.as_bytes()).expect("write public key");

        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let config = AuthorityConfigBuilder::new(authority_schema::AuthorityConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            policy_dir,
            issuance_policy_dir,
            revocation_file: dir.path().join("revocations.txt"),
            key_file: key_path,
            log_level: "warn".to_string(),
            ..authority_schema::AuthorityConfig::default()
        })
        .build()
        .expect("valid authority config");
        let server = Server::try_new(config, async {
            let _ = shutdown_rx.await;
        })
        .await
        .expect("start real Authority");
        let url = format!("http://127.0.0.1:{}", server.port());
        let handle = tokio::spawn(server.run());

        Self {
            url,
            pub_key_path,
            shutdown,
            handle,
            _dir: dir,
        }
    }

    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        self.handle
            .await
            .expect("join real Authority")
            .expect("run real Authority");
    }
}
