//! Build the connector [`ConnectorRegistry`] from `[sidecar.connector]` config.
//!
//! The registry default is built from `default_timeout` (30s uses
//! the [`GenericHttpConnector::default_for_unconfigured`] shortcut);
//! every host connector entry becomes a
//! [`GenericHttpConnector`] registered under its host string.

use std::sync::Arc;

use crate::config;
use crate::connector::ConnectorRegistry;
use crate::connector::provider::{GenericHttpConnector, HttpConnectorConfig, RateLimitConfig};

/// Builds the [`ConnectorRegistry`] from the `[sidecar.connector]` config
/// section.
///
/// # Errors
///
/// Returns an error when a [`GenericHttpConnector`] cannot be built
/// (TLS setup failure).
pub fn build_connector_registry(
    cfg: &config::ConnectorConfig,
) -> anyhow::Result<Arc<ConnectorRegistry>> {
    let default = if cfg.default_timeout
        == firma_config_utils::NonZeroDuration::from_static(std::time::Duration::from_secs(30))
    {
        GenericHttpConnector::default_for_unconfigured()
    } else {
        GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: cfg.default_timeout,
            rate_limit: None,
        })
    }
    .map_err(|e| anyhow::anyhow!("failed to build default connector: {e}"))?;

    let mut registry = ConnectorRegistry::new(Arc::new(default));

    for host_cfg in &cfg.hosts {
        let http = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: host_cfg.timeout,
            rate_limit: Some(RateLimitConfig {
                rps: host_cfg.rps,
                burst: host_cfg.burst,
            }),
        })
        .map_err(|e| anyhow::anyhow!("failed to build connector for {}: {e}", host_cfg.host))?;
        registry.register_host(host_cfg.host.clone(), Arc::new(http));
        tracing::debug!(
            host = host_cfg.host.as_str(),
            rps = host_cfg.rps,
            burst = host_cfg.burst,
            timeout_ms = u64::try_from(host_cfg.timeout.duration().as_millis()).unwrap_or(u64::MAX),
            "connector host override registered"
        );
    }

    Ok(Arc::new(registry))
}
