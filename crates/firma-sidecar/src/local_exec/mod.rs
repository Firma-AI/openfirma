//! Local-exec governance endpoint.
//!
//! This module implements the Sidecar-owned UDS endpoint that `firma-run`
//! contacts for pre-execution governance decisions on local tool invocations.
//!
//! It is the authoritative implementation of the "mediator" role described in
//! the canonical docs:
//! - `docs/architecture/linux-local-command-enforcement.md`
//! - `docs/architecture/command-governance-local-exec-contract.md`
//!
//! Principle: **one control plane and one audit surface**.
//! The mock Python scripts in `examples/` exercise the wire protocol but are
//! not production components.
//!
//! # Sub-modules
//!
//! - [`token_store`] — Approval token state machine (`Pending → Approved →
//!   Consumed / Expired / Revoked`). Enforces single-use, short-lived,
//!   context-bound tokens; operator must explicitly approve before a token can
//!   be consumed.
//! - [`handler`] — Decision logic. Processes one [`handler::LocalExecRequest`]
//!   and returns a [`handler::LocalExecResponse`], and processes management
//!   commands ([`handler::LocalExecManagementRequest`]) via `decide_management`.
//! - [`endpoint`] — Async UDS listener. Binds the socket, accepts connections,
//!   dispatches to the handler (governance or management), and manages the
//!   pruning task lifecycle.

pub(crate) mod endpoint;
pub mod handler;
pub mod token_store;

pub(crate) use self::endpoint::LocalExecEndpoint;
pub(crate) use self::handler::DefaultAction;
pub use self::handler::{LocalExecDecision, LocalExecHandler, LocalExecHandlerConfig};
pub use self::token_store::{ApproveResult, RevokeResult, TokenStore};
