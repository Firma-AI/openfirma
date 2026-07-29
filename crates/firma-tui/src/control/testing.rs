//! Headless runner support for integration tests.
//!
//! Tests crank the control loop through this surface instead of entering raw
//! terminal mode. We keep these runner hooks here so the CLI-facing control
//! API stays focused on runtime behavior.

pub use super::runner::{ControlCrankOutcome, EventKind, HeadlessRunner, ProcessedEventProbe};
