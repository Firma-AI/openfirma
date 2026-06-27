//! Compiles the `firma.v1` wire contract into Rust types at build time.
//!
//! The `.proto` sources under `proto/firma/v1/` are the single source of truth
//! shared with `firma-team`'s Authority. They are compiled into Rust types and
//! Tonic service glue via `tonic-prost-build`, producing both client and server
//! stubs (openfirma's Sidecar drives the client; the Authority serves the
//! server). Relies on a system `protoc`, matching the rest of the workspace.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/firma/v1/types.proto",
        "proto/firma/v1/authority.proto",
        "proto/firma/v1/audit.proto",
    ];
    let includes = ["proto"];

    tonic_prost_build::configure().compile_protos(&protos, &includes)?;

    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}
