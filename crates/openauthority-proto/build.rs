fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure().compile_protos(
        &[
            "proto/openauthority/v1/types.proto",
            "proto/openauthority/v1/authority.proto",
            "proto/openauthority/v1/audit.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
