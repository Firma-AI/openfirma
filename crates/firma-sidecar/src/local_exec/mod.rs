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
//!
//! # Management authentication
//!
//! Governance requests (`local.exec`) and management commands
//! (`local.exec.approve` / `local.exec.revoke`) share the same UDS, and the
//! sandboxed agent runs as the Sidecar's UID and can reach the socket. To stop
//! the agent from self-approving its own pending HITL tokens, management
//! commands require an operator [`handler::RedactedManagementToken`] (configured
//! via `local_exec.management_token_env` / `management_token_path`, constant-time
//! compared). When no token is configured, management is disabled fail-closed.

pub mod endpoint;
pub mod handler;
pub mod token_store;

pub use self::endpoint::LocalExecEndpoint;
pub use self::handler::{
    DefaultAction, LocalExecDecision, LocalExecHandler, LocalExecHandlerConfig,
    LocalExecManagementRequest, LocalExecManagementResponse, ManagementOutcome,
    RedactedManagementToken,
};
pub use self::token_store::{ApproveResult, RevokeResult, TokenStore};
