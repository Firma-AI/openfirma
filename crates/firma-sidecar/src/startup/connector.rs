//! [`ConnectorRegistry`] construction from the `[connector]` config.
//!
//! The registry default is built from `default_timeout_ms` (30s uses
//! the [`GenericHttpConnector::default_for_unconfigured`] shortcut);
//! every [`HostConnectorConfig`] entry becomes a
//! [`GenericHttpConnector`] registered under its host string.

use std::num::NonZeroU32;
use std::sync::Arc;

use crate::config;
use crate::connector::ConnectorRegistry;
use crate::connector::provider::{GenericHttpConnector, HttpConnectorConfig, RateLimitConfig};

/// Builds the [`ConnectorRegistry`] from the `[connector]` config
/// section.
///
/// # Errors
///
/// Returns an error when a [`GenericHttpConnector`] cannot be built
/// (TLS setup failure) or when the host rate-limit parameters are
/// zero (validation should have already caught this).
pub fn build_connector_registry(
    cfg: &config::ConnectorConfig,
) -> anyhow::Result<Arc<ConnectorRegistry>> {
    let default = if cfg.default_timeout_ms == 30_000 {
        GenericHttpConnector::default_for_unconfigured()
    } else {
        GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: std::time::Duration::from_millis(cfg.default_timeout_ms),
            rate_limit: None,
        })
    }
    .map_err(|e| anyhow::anyhow!("failed to build default connector: {e}"))?;

    let mut registry = ConnectorRegistry::new(Arc::new(default));

    for host_cfg in &cfg.hosts {
        let rps = NonZeroU32::new(host_cfg.rps)
            .ok_or_else(|| anyhow::anyhow!("connector host {}: rps must be > 0", host_cfg.host))?;
        let burst = NonZeroU32::new(host_cfg.burst).ok_or_else(|| {
            anyhow::anyhow!("connector host {}: burst must be > 0", host_cfg.host)
        })?;
        let http = GenericHttpConnector::new(&HttpConnectorConfig {
            timeout: std::time::Duration::from_millis(host_cfg.timeout_ms),
            rate_limit: Some(RateLimitConfig { rps, burst }),
        })
        .map_err(|e| anyhow::anyhow!("failed to build connector for {}: {e}", host_cfg.host))?;
        registry.register_host(host_cfg.host.clone(), Arc::new(http));
        tracing::info!(
            host = host_cfg.host.as_str(),
            rps = host_cfg.rps,
            burst = host_cfg.burst,
            timeout_ms = host_cfg.timeout_ms,
            "connector host override registered"
        );
    }

    Ok(Arc::new(registry))
}
