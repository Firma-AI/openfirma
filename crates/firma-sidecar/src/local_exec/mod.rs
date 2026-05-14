//! Local-exec governance endpoint.
//!
//! This module implements the Sidecar-owned UDS endpoint that `firma-run`
//! contacts for pre-execution governance decisions on local tool invocations.
//!
//! It is the authoritative implementation of the "mediator" role described in
//! the FIR-115 architecture: **one control plane, one audit surface, one
//! budget state**. The mock Python scripts in `examples/` exercise the wire
//! protocol but are not production components.
//!
//! # Sub-modules
//!
//! - [`token_store`] — Approval token state machine (pending → consumed /
//!   expired). Enforces single-use, short-lived, context-bound tokens.
//! - [`handler`] — Stateless decision logic. Processes one
//!   [`handler::LocalExecRequest`] and returns a [`handler::LocalExecResponse`].
//! - [`endpoint`] — Async UDS listener. Binds the socket, accepts connections,
//!   dispatches to the handler, and manages the pruning task lifecycle.

pub mod endpoint;
pub mod handler;
pub mod token_store;

pub use self::endpoint::LocalExecEndpoint;
pub use self::handler::{DefaultAction, LocalExecDecision, LocalExecHandler, LocalExecHandlerConfig};
pub use self::token_store::TokenStore;
