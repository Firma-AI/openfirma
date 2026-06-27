//! Rust bindings for the Firma `firma.v1` Protobuf/gRPC wire contract.
//!
//! This crate is the in-tree source of the `firma-protobuf` contract: it
//! compiles the `.proto` definitions under `proto/firma/v1/` into Rust types
//! and Tonic service glue. It is the single source of truth for the Authority,
//! Sidecar, and audit wire formats, consumed by
//! [openfirma](https://github.com/Firma-AI/openfirma) and
//! [firma-team](https://github.com/Firma-AI/firma-team).
//!
//! All generated items live under [`v1`]. Both gRPC client and server stubs are
//! generated:
//!
//! - [`v1::authority_service_client`] / [`v1::authority_service_server`]
//! - [`v1::audit_service_client`] / [`v1::audit_service_server`]
//!
//! # Wire compatibility
//!
//! The contract is versioned by package. Backward-compatible changes add fields
//! with new tag numbers; existing field numbers are never reused or renumbered.
//! A breaking change requires a new package version (`firma.v2`).

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

/// Generated types and Tonic service glue for the `firma.v1` package.
pub mod v1 {
    #![allow(
        clippy::allow_attributes,
        reason = "prost/tonic emits outer #[allow(...)] attributes in generated Rust"
    )]
    tonic::include_proto!("firma.v1");
}