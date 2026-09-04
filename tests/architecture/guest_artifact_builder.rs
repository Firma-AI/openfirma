use std::fs;

#[test]
fn vz_guest_builder_binds_the_built_shim_into_its_manifest() -> Result<(), anyhow::Error> {
    let graph = crate::metadata::load()?;
    let workspace_root = graph.workspace().root();
    let script =
        fs::read_to_string(workspace_root.join("scripts/macos-vz/build-guest-artifacts.sh"))?;

    assert_eq!(
        script.matches("--target-dir \"$cargo_target_dir\"").count(),
        2,
        "both guest binaries must be read from builder-owned Cargo output"
    );

    let build = script
        .find("--bin firma-secret-shim")
        .ok_or_else(|| anyhow::anyhow!("guest builder does not build firma-secret-shim"))?;
    let copy = script
        .find("cp \"$guest_secret_shim\" \"$out_dir/firma-secret-shim\"")
        .ok_or_else(|| {
            anyhow::anyhow!("guest builder does not copy the built shim into the bundle")
        })?;
    let manifest = script
        .find("shim_sha256=$(sha256_file \"$out_dir/firma-secret-shim\")")
        .ok_or_else(|| anyhow::anyhow!("guest manifest does not hash the bundled shim"))?;

    assert!(
        build < copy && copy < manifest,
        "the shim must be built, copied into the bundle, then hashed"
    );
    Ok(())
}
