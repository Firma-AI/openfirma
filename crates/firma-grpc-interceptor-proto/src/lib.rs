// Firma gRPC Interceptor Proto — agent-facing interceptor hook definitions.
//
// This crate owns the wire contract between an agent and the Firma Sidecar
// interceptor. It is intentionally separate from `firma-protobuf`, which carries
// the Authority ↔ Sidecar contract.
//
// All types are generated from `.proto` files via prost/tonic.
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
    pub mod interceptor {
        pub mod v1 {
            #![allow(
                clippy::allow_attributes,
                reason = "prost/tonic emits outer #[allow(...)] attributes in generated Rust"
            )]
            tonic::include_proto!("firma.interceptor.v1");
        }
    }
}

// Re-export commonly used types at crate root for ergonomics.
pub use firma::interceptor::v1::*;
