// Firma Proto — gRPC service definitions and wire contract types.
//
// This crate is the single source of truth for the Firma wire contract.
// All inter-service types are generated from `.proto` files via prost/tonic.
//
// Do not hand-write Rust types that duplicate proto messages.

// Allow clippy lints that fire on generated code.
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_long_first_doc_paragraph)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::wildcard_imports)]

pub mod firma {
    pub mod v1 {
        tonic::include_proto!("firma.v1");
    }
}

// Re-export commonly used types at crate root for ergonomics.
pub use firma::v1::*;

// Re-export prost_types so downstream crates can reference proto
// well-known types (e.g. Timestamp) without a direct dependency.
pub use prost_types;
