fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure().compile_protos(
        &["proto/openauthority/interceptor/v1/interceptor.proto"],
        &["proto"],
    )?;
    Ok(())
}
