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
