//! Cedar policy tooling for the `firma policy` subcommand.
//!
//! Hosts the offline policy developer-experience commands:
//!
//! - [`validate`] parses a Cedar policy file and type-checks it against the
//!   canonical Firma schema ([`firma_core::cedar::FIRMA_SCHEMA`]).
//! - [`test_fixture`] evaluates a TOML fixture against a `*.cedar` bundle
//!   directory ([`bundle`]) and compares the decision to the fixture's
//!   expectation, reusing the Sidecar hot-path request construction so a
//!   fixture verdict equals enforcement. [`fixture`] owns the fixture model
//!   and context merge.
//!
//! All entry points are fully local and fail-closed: any I/O, parse, schema,
//! or validation failure surfaces a diagnostic on stderr and a non-zero exit
//! code; no path silently exits 0.

pub mod bundle;
pub mod fixture;
pub mod test_fixture;
pub mod validate;
