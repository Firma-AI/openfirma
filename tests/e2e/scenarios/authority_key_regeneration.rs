use crate::harness::TestWorld;

#[test]
fn run_executes_echo_after_authority_key_was_wiped() {
    let world = TestWorld::isolated();
    let config_dir = world.path("config");
    let state_dir = world.state_path();
    let workspace = world.workspace_path();
    world.scaffold_config(
        "generic",
        &config_dir,
        &state_dir,
        Some(&workspace),
        &workspace,
    );
    TestWorld::disable_host_home_masks(&config_dir.join("firma.toml"));

    let key_file = state_dir.join("authority.key");
    assert!(key_file.is_file(), "config should have generated the key");
    std::fs::remove_file(&key_file).expect("remove authority key");
    let _ = std::fs::remove_file(state_dir.join("authority.pub"));
    assert!(!key_file.exists(), "precondition: key absent before run");

    let output = world.run_firma(
        "generic",
        Some(&config_dir.join("firma.toml")),
        &workspace,
        &[],
        "echo",
        ["hello"],
    );
    assert!(
        output.success(),
        "firma run failed (regression?):\n{output}"
    );
    assert!(
        output.stdout.contains("hello"),
        "expected 'hello' from the sandboxed command:\n{output}"
    );
    assert!(
        key_file.is_file(),
        "authority key should have been regenerated on demand"
    );
}
