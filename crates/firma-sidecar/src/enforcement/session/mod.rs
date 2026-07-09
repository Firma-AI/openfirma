//! Session-state store: per-session runtime context for Stage 2.
//!
//! Contains the [`SessionStateStore`] trait, the in-memory [`LruSessionStateStore`]
//! (default), and the file-backed [`PersistentSessionStateStore`] (opt-in via
//! `constraint_enforcement.session_state_backend = "persistent"`).
//!
//! # Module layout
//!
//! - [`state`] — trait, types (`RuntimeSignals`, `Outcome`, `ActionOutcome`,
//!   `SessionRecord`), and the LRU backend.
//! - [`persistent`] — JSONL-backed persistent backend.

pub mod persistent;
pub mod state;

pub use persistent::PersistentSessionStateStore;
pub use state::{ActionOutcome, LruSessionStateStore, Outcome, RuntimeSignals, SessionStateStore};
