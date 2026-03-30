fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(
        &[
            "proto/firma/v1/types.proto",
            "proto/firma/v1/authority.proto",
        ],
        &["proto"],
    )?;
    Ok(())
}
