//! Tenancy configuration for the sidecar.
//!
//! The representation lives in `firma-config-schema`. This section carries no
//! validation, so the schema types are re-exported directly and used as-is.

pub use firma_config_schema::sidecar::tenancy::TenancyConfig;
