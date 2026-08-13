//! Unified `firma.toml` resolution round-trips.

use firma_config_loader::CONFIG_FILE_NAME;
use firma_stack::{StackError, resolve_stack_config};

#[test]
fn resolves_explicit_override() {
    let dir = tempfile::tempdir().expect("dir");
    let cfg_path = dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(
        &cfg_path,
        "[authority]\nlisten_addr = \"127.0.0.1:50051\"\n\
         [sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"127.0.0.1:8080\"\n",
    )
    .expect("write");
    let cfg = resolve_stack_config(Some(&cfg_path)).expect("resolve");
    assert_eq!(cfg.config_file, cfg_path);
    assert!(cfg.firma_bin.is_none());
}

#[test]
fn explicit_override_errors_if_missing() {
    let cfg_path = std::path::Path::new("/definitely/not/here/firma.toml");
    let error = resolve_stack_config(Some(cfg_path)).expect_err("missing override must fail");
    let StackError::ConfigResolution { source } = error else {
        panic!("expected typed config resolution error, got {error:?}");
    };
    assert_eq!(source.path, cfg_path);
}
