//! Connector trait and shared types for outbound request dispatch.
//!
//! The connector is the layer that runs **after** enforcement and
//! credential injection have produced an authorised
//! [`TransportView`]. Its job is precise and bounded by FEP §6.2:
//! translate the envelope into the target wire format, apply
//! technical constraints (rate limit, timeout, connection pool),
//! merge injected credentials into the outbound request, and return
//! the target response.
//!
//! ## Scope
//!
//! The connector layer is **not** an enforcement layer. By the time a
//! request reaches it, Stage 1 (capability validation), Stage 2
//! (constraint enforcement), and credential injection have all run.
//! Implementations must not:
//!
//! - make authorization decisions,
//! - modify intent or capability fields on the envelope,
//! - implement business logic,
//! - source credentials independently of the [`TransportView`].
//!
//! Implementations **may**:
//!
//! - translate the envelope into the target wire format,
//! - apply technical constraints (rate limit, timeout, connection
//!   pool),
//! - read credentials from the [`TransportView`] and merge them into
//!   the outbound request,
//! - enrich audit metadata with outcome information returned via
//!   [`ConnectorResponse`].
//!
//! ## Extensibility
//!
//! The trait and its associated types live in `firma-core` so that
//! external crates can implement specialized connectors (LLM
//! providers, databases, tool APIs) without pulling in the sidecar
//! binary. The sidecar owns the registry and the generic HTTP
//! implementation; specialized connectors plug in as host overrides.
//!
//! ## Example
//!
//! A minimal connector that echoes the request body back as the
//! response body:
//!
//! ```
//! use std::collections::HashMap;
//! use std::time::Duration;
//!
//! use async_trait::async_trait;
//! use firma_core::{
//!     ActionParams, Connector, ConnectorError, ConnectorResponse, TransportView,
//! };
//!
//! struct EchoConnector;
//!
//! #[async_trait]
//! impl Connector for EchoConnector {
//!     async fn dispatch(
//!         &self,
//!         view: &TransportView,
//!     ) -> Result<ConnectorResponse, ConnectorError> {
//!         let body = match &view.envelope().intent().params {
//!             ActionParams::Http(http) => http.body.clone().unwrap_or_default(),
//!             _ => Vec::new(),
//!         };
//!         let response_size = body.len();
//!         Ok(ConnectorResponse {
//!             status: 200,
//!             headers: HashMap::new(),
//!             body,
//!             dispatch_latency: Duration::from_millis(0),
//!             response_size,
//!         })
//!     }
//! }
//! ```

use std::time::Duration;

use async_trait::async_trait;
use firma_http::HeaderMap;

use crate::transport::TransportView;

/// Translates an authorised [`TransportView`] into a target call and
/// returns the response.
///
/// Implementations are responsible only for protocol translation,
/// technical constraints (rate limit, timeout, connection pooling),
/// and credential merging from the view. Enforcement, capability
/// verification, and credential sourcing happen upstream of this
/// trait — see the module-level documentation for the boundary rules.
///
/// The trait uses [`macro@async_trait`] because connector instances are
/// consumed as `Arc<dyn Connector>` through the sidecar registry, and
/// native `async fn` in traits does not yet support `dyn` under this
/// workspace's configuration.
///
/// # Errors
///
/// Implementations return [`ConnectorError`] on dispatch failure. See
/// the variants on that type for the expected mapping.
#[async_trait]
pub trait Connector: Send + Sync {
    /// Dispatches the request described by `view` to the target
    /// system and returns a [`ConnectorResponse`].
    ///
    /// Implementations must read the envelope and credentials through
    /// `view` only; they must not source credentials from any other
    /// location.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorError`] when the dispatch cannot complete:
    ///
    /// - [`ConnectorError::Timeout`] when the rate limiter wait or
    ///   the upstream call exceeds the configured timeout.
    /// - [`ConnectorError::Network`] on transport failures (DNS,
    ///   TCP, TLS, connection reset).
    /// - [`ConnectorError::InvalidRequest`] when the envelope cannot
    ///   be translated into a well-formed target request. This
    ///   should be unreachable post-enforcement; callers treat it
    ///   as fail-closed.
    ///
    /// A target-side error status (4xx or 5xx) is **not** a
    /// connector error — it is returned as an [`Ok`] variant with
    /// the status populated, so the caller can relay it to the
    /// agent.
    async fn dispatch(&self, view: &TransportView) -> Result<ConnectorResponse, ConnectorError>;
}

/// Response returned from a successful connector dispatch.
///
/// Carries the raw target response (status, headers, body) together
/// with outcome metadata that the sidecar uses to enrich the audit
/// event emitted for the call.
///
/// `response_size` is pre-computed from `body.len()` so the audit
/// enrichment path does not have to re-measure the body.
#[derive(Debug, Clone)]
pub struct ConnectorResponse {
    /// HTTP-style status code returned by the target.
    ///
    /// Set to the upstream code even when it is a 4xx or 5xx — those
    /// are not connector errors and must be relayed unchanged to the
    /// agent.
    pub status: u16,
    /// Response headers returned by the target.
    pub headers: HeaderMap,
    /// Raw response body bytes returned by the target.
    pub body: Vec<u8>,
    /// Wall-clock latency measured around the dispatch call.
    ///
    /// Covers the outbound request and the inbound response read.
    /// Used by the audit enrichment path.
    pub dispatch_latency: Duration,
    /// Byte length of [`body`](Self::body), pre-computed for audit.
    pub response_size: usize,
}

/// Failure mode reported by a [`Connector`] implementation.
///
/// Variants map onto transport-level outcomes that the sidecar
/// translates into either an [`Aborted`] or a [`Deny`] response. See
/// the connector task specification (task 005) for the full table.
///
/// Target-side 4xx / 5xx responses are **not** represented here; they
/// are returned as [`ConnectorResponse`] with the upstream status
/// populated.
///
/// [`Aborted`]: #
/// [`Deny`]: #
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// Dispatch exceeded the configured timeout.
    ///
    /// Covers both the per-host timeout on the upstream call and the
    /// rate-limiter queue wait when the queue depth pushes the total
    /// wait beyond the timeout. Surfaced to the agent as an ABORT
    /// with reason `CONNECTOR_TIMEOUT`.
    #[error("connector timeout after {0:?}")]
    Timeout(Duration),

    /// Transport-layer failure reaching the target.
    ///
    /// Examples: DNS resolution failure, TCP refused, TLS handshake
    /// failure, connection reset mid-response. Surfaced to the agent
    /// as a DENY with reason `CONNECTOR_NETWORK_ERROR`.
    #[error("network error: {0}")]
    Network(String),

    /// The envelope could not be translated into a well-formed
    /// target request.
    ///
    /// Should be unreachable once enforcement has approved the call;
    /// the sidecar treats this fail-closed and emits a DENY with
    /// reason `CONNECTOR_INVALID_REQUEST`.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_error_timeout_display() {
        let err = ConnectorError::Timeout(Duration::from_secs(30));
        assert_eq!(err.to_string(), "connector timeout after 30s");
    }

    #[test]
    fn test_connector_error_network_display() {
        let err = ConnectorError::Network("dns lookup failed".to_string());
        assert_eq!(err.to_string(), "network error: dns lookup failed");
    }

    #[test]
    fn test_connector_error_invalid_request_display() {
        let err = ConnectorError::InvalidRequest("missing method".to_string());
        assert_eq!(err.to_string(), "invalid request: missing method");
    }

    #[test]
    fn test_connector_error_is_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<ConnectorError>();
    }

    #[test]
    fn test_connector_response_debug() {
        let resp = ConnectorResponse {
            status: 200,
            headers: HeaderMap::new(),
            body: Vec::new(),
            dispatch_latency: Duration::from_millis(0),
            response_size: 0,
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("ConnectorResponse"));
    }

    #[test]
    fn test_connector_response_clone() {
        let resp = ConnectorResponse {
            status: 201,
            headers: HeaderMap::from([(
                http::HeaderName::from_static("X-Test"),
                http::HeaderValue::from_static("1"),
            )]),
            body: vec![1, 2, 3],
            dispatch_latency: Duration::from_millis(5),
            response_size: 3,
        };
        let cloned = resp.clone();
        assert_eq!(cloned.status, resp.status);
        assert_eq!(cloned.headers, resp.headers);
        assert_eq!(cloned.body, resp.body);
        assert_eq!(cloned.dispatch_latency, resp.dispatch_latency);
        assert_eq!(cloned.response_size, resp.response_size);
    }
}
