//! Unified `firma.toml` resolution round-trips.

use firma_stack::resolve_stack_config;

#[test]
fn resolves_explicit_override() {
    let dir = tempfile::tempdir().expect("dir");
    let cfg_path = dir.path().join("firma.toml");
    std::fs::write(
        &cfg_path,
        "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n\
         [sidecar.interceptor]\nlisten_addr = \"127.0.0.1:8080\"\n",
    )
    .expect("write");
    let cfg = resolve_stack_config(Some(&cfg_path)).expect("resolve");
    assert_eq!(cfg.config_file, cfg_path);
    assert!(cfg.state_dir.is_none());
    assert!(cfg.firma_bin.is_none());
}

#[test]
fn explicit_override_round_trips_even_if_missing() {
    // resolve_config trusts an explicit --config flag (Flag source); the
    // not-found branch only triggers during discovery.
    let cfg_path = std::path::Path::new("/definitely/not/here/firma.toml");
    let cfg = resolve_stack_config(Some(cfg_path)).expect("resolve");
    assert_eq!(cfg.config_file, cfg_path);
}
