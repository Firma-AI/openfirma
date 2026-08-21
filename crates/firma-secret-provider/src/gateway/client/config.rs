//! Secret-gateway client tuning.
//!
//! The representation lives in `firma-config-schema` (the single source of
//! truth for config shape). Re-exported here so the canonical
//! `firma_secret_provider::gateway::client::config::GatewayClientConfig` path —
//! and every consumer — stays unchanged.

pub use firma_config_schema::gateway::GatewayClientConfig;
