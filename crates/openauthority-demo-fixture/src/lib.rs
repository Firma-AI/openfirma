//! Shared bits for the demo fixture server and the CI driver client.
//!
//! Two binaries live in this crate:
//!
//! - `openauthority-demo-fixture` — HTTP server with `/allow`, `POST /deny`,
//!   `/_ping` routes used as the deterministic CI target.
//! - `openauthority-demo-fixture-client` — CLI that drives both routes through
//!   the sidecar proxy and asserts ALLOW + DENY shape.
//!
//! The library surface is intentionally thin: just the canonical
//! response bodies so the server and the client agree on what counts
//! as a passing CI run.

/// Default fixture listen address.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9100";

/// JSON body returned by the fixture for `GET /allow`.
pub const ALLOW_BODY_JSON: &str = r#"{"ok":true,"path":"/allow"}"#;

/// JSON body returned by the fixture for `POST /deny` when the
/// upstream policy is misconfigured. The sidecar should always block
/// before the request reaches the fixture; this body exists only as a
/// positive control for that misconfiguration scenario.
pub const DENY_BODY_JSON: &str = r#"{"would":"leak"}"#;

/// Plaintext body for `GET /_ping`.
pub const PING_BODY_TEXT: &str = "ok";
