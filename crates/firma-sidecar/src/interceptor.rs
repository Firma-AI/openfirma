//! Interceptor.
//!
//! Captures outbound agent traffic before it reaches the external system.
//! Three modes: HTTP proxy (port 8080 default), gRPC hook (programmatic
//! interceptor within the agent process), and Unix socket (avoids port
//! binding in containers). eBPF capture is on the roadmap.
//!
//! Regardless of interception mode, the raw intercepted request is converted
//! into a [`RawRequest`](crate::normalizer::RawRequest) and passed to the
//! [`EnforcementPipeline`](crate::pipeline::EnforcementPipeline) for
//! enforcement. If the intercepted request cannot be parsed into a valid
//! `RawRequest`, the interceptor returns a structured DENY with reason
//! `MALFORMED_REQUEST` (fail-closed).

pub mod grpc;
pub mod http;
#[cfg(unix)]
#[cfg_attr(docsrs, doc(cfg(unix)))]
pub mod unix_socket;

use std::sync::Arc;

use crate::pipeline::EnforcementPipeline;

use tokio_util::sync::CancellationToken;

/// An error that can occur on an [`Interceptor`].
#[derive(Debug, thiserror::Error)]
pub enum InterceptorError {
    /// The interceptor failed to bind to the configured address or socket path.
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// An unrecoverable server error occurred while the interceptor was running.
    #[error("server error: {0}")]
    ServerError(String),
}

/// Entry point that captures outbound agent traffic before it reaches external systems.
///
/// Every outbound agent call must pass through an [`Interceptor`] before reaching
/// the target. The interceptor converts transport-specific input into a
/// [`RawRequest`](crate::normalizer::RawRequest), runs it through the
/// [`EnforcementPipeline`], and acts on the resulting
/// [`EnforcementDecision`](crate::pipeline::EnforcementDecision) at the
/// transport level (forward on Allow/Passthrough, reject on Deny).
///
/// Three interception modes are supported today:
///
/// | Mode | Description |
/// |------|-------------|
/// | **HTTP proxy** | Listens on a configurable TCP port (default 8080). The agent sets `HTTP_PROXY=http://localhost:<port>`. |
/// | **gRPC hook** | Programmatic interceptor registered within the agent process — no port binding required. |
/// | **Unix socket** | Listens on a local Unix domain socket, avoiding port conflicts in containers. |
///
/// An eBPF kernel-level capture mode is on the roadmap but out of scope for V1.
///
/// # Contract
///
/// * The implementor **must** build a
///   [`RawRequest`](crate::normalizer::RawRequest) from the incoming
///   transport data and call
///   [`EnforcementPipeline::enforce`] to obtain a decision.
/// * If a request cannot be parsed into a valid
///   [`RawRequest`](crate::normalizer::RawRequest), the implementor
///   **must** reply to the caller with a structured DENY carrying reason
///   `MALFORMED_REQUEST` (fail-closed).
/// * On [`EnforcementDecision::Allow`](crate::pipeline::EnforcementDecision)
///   or [`EnforcementDecision::Passthrough`](crate::pipeline::EnforcementDecision),
///   the implementor forwards the request to the upstream.
/// * On [`EnforcementDecision::Deny`](crate::pipeline::EnforcementDecision),
///   the implementor returns a structured denial to the caller.
/// * The implementor **must** stop accepting new connections and drain
///   in-flight work when `cancel` is triggered, then return `Ok(())`.
///
/// # Errors
///
/// Returns [`InterceptorError`] if the interceptor encounters an
/// unrecoverable error.
pub trait Interceptor: Send + Sync + 'static {
    /// Starts the interceptor loop, enforcing each request via `pipeline`.
    ///
    /// This method runs until `cancel` is triggered or an unrecoverable
    /// error occurs. Implementors should treat this as the main run loop
    /// for the interception mode.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptorError`] on unrecoverable failure.
    fn run(
        self,
        pipeline: Arc<EnforcementPipeline>,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<(), InterceptorError>>;
}
