//! Secret broker dispatch for `firma run`.
//!
//! The broker keeps real secret values out of the agent: each value is stored
//! under an opaque `fsp_` placeholder and the agent only ever sees the token.
//! The canonical dictionary (`SecretStore`) and transport (`BrokerListener`/`BrokerClient`)
//! live in `firma-secret-provider`; this module owns the per-request dispatch
//! (`serve`) and the accept loop (`accept`) that wire a shim request to a real
//! vault CLI execution plus extraction.

/// Broker accept loop: accept shim connections, classify, and serve them.
pub mod accept;

/// Per-request broker dispatch: run the real vault CLI and apply the extraction
/// transform by decision (fail-closed).
pub mod serve;
