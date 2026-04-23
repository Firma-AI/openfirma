//! In-tree [`Connector`](firma_core::Connector) implementations.
//!
//! Currently ships a single generic HTTP connector
//! ([`GenericHttpConnector`]) used as the registry default and for
//! every host that does not have a specialized override. Additional
//! providers (gRPC, SQL, specialized API clients) are added here when
//! they are built.
//!
//! External crates implementing the core [`Connector`] trait are
//! plugged in at startup via
//! [`ConnectorRegistry::register_host`](super::ConnectorRegistry::register_host).

mod http;

pub use self::http::{GenericHttpConnector, HttpConnectorConfig, RateLimitConfig};
