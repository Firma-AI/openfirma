//! Compiles the `firma.v1` wire contract into Rust types at build time.
//!
//! The `.proto` sources under `proto/firma/v1/` are the single source of truth
//! shared with openfirma and firma-team. They are bundled into the published
//! crate (see `include` in `Cargo.toml`) so the compile runs identically from a
//! git checkout and from a crates.io download. `protoc` is vendored via
//! `protoc-bin-vendored`, so no system `protoc` is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/firma/v1/types.proto",
        "proto/firma/v1/authority.proto",
        "proto/firma/v1/audit.proto",
    ];
    let includes = ["proto"];

    let mut prost_config = prost_build::Config::new();
    prost_config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    // The granted arm of the outcome oneof embeds a full CapabilityToken and
    // dwarfs the other variants; boxing it keeps the generated enum small
    // (clippy::large_enum_variant under `-D warnings`).
    prost_config.boxed(".firma.v1.GetApprovalOutcomeResponse.outcome.granted");

    // Generate both client and server glue: openfirma's Sidecar drives the
    // client, firma-team's Authority serves the server.
    tonic_prost_build::configure().compile_with_config(prost_config, &protos, &includes)?;

    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    Ok(())
}
