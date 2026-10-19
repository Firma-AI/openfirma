use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use firma_config_schema::authority::AuthorityConfig;

pub struct LocalAuthority {
    child: Child,
    pub url: String,
    pub public_key: PathBuf,
}

impl LocalAuthority {
    pub(super) fn start(root: &Path, policies: &Path, mappings: &Path) -> anyhow::Result<Self> {
        Self::start_configured(root, policies, mappings, |_| {})
    }

    /// Starts with a generated key after `configure` adjusts the fixture config.
    pub(super) fn start_configured(
        root: &Path,
        policies: &Path,
        mappings: &Path,
        configure: impl FnOnce(&mut AuthorityConfig),
    ) -> anyhow::Result<Self> {
        let key = root.join("authority.key");
        let output = Command::new(env!("CARGO_BIN_EXE_firma"))
            .args(["authority", "generate-key", "--output"])
            .arg(&key)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "generate-key failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self::launch(root, policies, mappings, &key, configure)
    }

    pub(super) fn start_with_key(
        root: &Path,
        policies: &Path,
        mappings: &Path,
        key: &Path,
    ) -> anyhow::Result<Self> {
        Self::launch(root, policies, mappings, key, |_| {})
    }

    fn launch(
        root: &Path,
        policies: &Path,
        mappings: &Path,
        key: &Path,
        configure: impl FnOnce(&mut AuthorityConfig),
    ) -> anyhow::Result<Self> {
        let config = root.join("authority-fixture.toml");
        let mut authority_config = AuthorityConfig {
            listen_addr: "127.0.0.1:0".into(),
            policy_dir: policies.into(),
            issuance_policy_dir: policies.into(),
            mapping_rules_paths: vec![mappings.into()],
            key_file: Some(key.into()),
            revocation_file: Some(root.join("revocations.txt")),
            ..AuthorityConfig::default()
        };
        configure(&mut authority_config);
        super::config_fixture::write_section(&config, "authority", &authority_config)?;
        let report = root.join("authority-fixture.startup.toml");
        let stderr = root.join("authority-fixture.stderr.log");
        let child = Command::new(env!("CARGO_BIN_EXE_firma"))
            .args(["authority", "--no-tls", "--config"])
            .arg(config)
            .arg("--startup-report")
            .arg(&report)
            .env("FIRMA_STATE_DIR", root.join("authority-state"))
            // Reload triggers log at debug; tests count them in the stderr log.
            .env("FIRMA_LOG_FILTER", "info,firma_authority=debug")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr)?)
            .spawn()?;
        let mut authority = Self {
            child,
            url: String::new(),
            public_key: key.with_extension("pub"),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(content) = std::fs::read_to_string(&report) {
                let report: toml::Value = toml::from_str(&content)?;
                let endpoint = report
                    .get("endpoint")
                    .ok_or_else(|| anyhow::anyhow!("missing Authority endpoint"))?;
                let endpoint: firma_stack::ComponentEndpoint = endpoint.clone().try_into()?;
                match endpoint {
                    firma_stack::ComponentEndpoint::Tcp(address) => {
                        authority.url = format!("http://{address}");
                        return Ok(authority);
                    }
                    #[cfg(unix)]
                    firma_stack::ComponentEndpoint::Unix(_) => {
                        anyhow::bail!("Authority published Unix endpoint")
                    }
                }
            }
            if authority.child.try_wait()?.is_some() || Instant::now() >= deadline {
                anyhow::bail!(
                    "Authority did not publish readiness: {}",
                    std::fs::read_to_string(&stderr)?
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl LocalAuthority {
    /// Stops the Authority process so connected Sidecars stop receiving bundles.
    pub(super) fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for LocalAuthority {
    fn drop(&mut self) {
        self.stop();
    }
}
