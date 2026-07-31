//! Connector layer for the sidecar dispatch hot path.
//!
//! Combines three concerns:
//!
//! - a [`ConnectorRegistry`] that maps the target host to a
//!   [`Connector`](firma_core::Connector) implementation;
//! - a [`provider`] submodule containing the in-tree connector
//!   implementations (currently just the generic HTTP one);
//! - (future) adapters for out-of-tree connectors plugged in as host
//!   overrides.
//!
//! The trait and its associated types live in `firma-core` so that
//! external crates can implement connectors without depending on the
//! sidecar binary. The registry and the concrete implementations are
//! sidecar-private: they are consumed only by the
//! [`RequestHandler`](crate::handler::RequestHandler).

pub mod provider;
mod registry;

pub use self::registry::ConnectorRegistry;
