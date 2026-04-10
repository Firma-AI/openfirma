//! Interceptor.
//!
//! Captures outbound agent traffic before it reaches the external system.
//! Three modes: HTTP proxy (port 8080 default), gRPC hook (programmatic
//! interceptor within the agent process), and Unix socket (avoids port
//! binding in containers). eBPF capture is on the roadmap.
//!
//! Regardless of interception mode, the raw intercepted request is passed to
//! the Intent Normalizer for canonicalization before enforcement. If the
//! intercepted request cannot be parsed into a valid `ExecutionEnvelope`, the
//! Sidecar returns a structured DENY with reason `MALFORMED_REQUEST`.

use crate::normalizer::RawRequest;

use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;

/// An error that can occur on an [`Interceptor`].
#[derive(Debug, thiserror::Error)]
pub enum InterceptorError {
    #[error("channel closed")]
    ChannelClosed,
}

/// Entry point that captures outbound agent traffic before it reaches external systems.
///
/// Every outbound agent call must pass through an [`Interceptor`] before reaching
/// the target. The interceptor converts transport-specific input into a
/// [`RawRequest`] and forwards it to the enforcement pipeline via the provided
/// channel. Regardless of transport mode, the produced [`RawRequest`] is
/// identical in shape, so downstream stages (Intent Normalizer, Stage 1,
/// Stage 2) are transport-agnostic.
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
/// * The implementor **must** send every successfully parsed request into `tx`
///   as a [`RawRequest`].
/// * If a request cannot be parsed into a valid [`RawRequest`], the
///   implementor **must** reply to the caller with a structured DENY carrying
///   reason `MALFORMED_REQUEST` (fail-closed).
/// * The implementor **must** stop accepting new connections and drain
///   in-flight work when `cancel` is triggered, then return `Ok(())`.
///
/// # Errors
///
/// Returns [`InterceptorError::ChannelClosed`] if the receiver half of `tx`
/// is dropped before the interceptor shuts down.
pub trait Interceptor: Send + Sync + 'static {
    /// Starts the interceptor loop, forwarding parsed requests into `tx`.
    ///
    /// This method runs until `cancel` is triggered or the channel closes.
    /// Implementors should treat this as the main run loop for the
    /// interception mode.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptorError::ChannelClosed`] if the receiving end of
    /// `tx` is dropped while the interceptor is still running.
    fn run(
        self,
        tx: Sender<RawRequest>,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<(), InterceptorError>>;
}
