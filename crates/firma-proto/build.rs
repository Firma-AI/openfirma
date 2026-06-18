fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Proto definitions are sourced from the shared `firma-protobuf` submodule
    // checked out at the workspace root.
    tonic_prost_build::configure().compile_protos(
        &[
            "../../firma-protobuf/proto/firma/v1/types.proto",
            "../../firma-protobuf/proto/firma/v1/authority.proto",
            "../../firma-protobuf/proto/firma/v1/audit.proto",
        ],
        &["../../firma-protobuf/proto"],
    )?;
    Ok(())
}
