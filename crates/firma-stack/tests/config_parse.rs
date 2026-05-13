//! Stack config parse round-trips.

use std::io::Write;

use firma_stack::load_stack_config;
use tempfile::NamedTempFile;

#[test]
fn parses_minimal_config() {
    let mut file = NamedTempFile::new().expect("tempfile");
    writeln!(
        file,
        "authority_config = \"authority.toml\"\nsidecar_config = \"sidecar.toml\"\n"
    )
    .expect("write");
    let cfg = load_stack_config(file.path()).expect("parse");
    assert!(cfg.authority_config.ends_with("authority.toml"));
    assert!(cfg.sidecar_config.ends_with("sidecar.toml"));
    assert!(cfg.state_dir.is_none());
}

#[test]
fn errors_when_required_field_missing() {
    let mut file = NamedTempFile::new().expect("tempfile");
    writeln!(file, "sidecar_config = \"sidecar.toml\"\n").expect("write");
    let err = load_stack_config(file.path()).expect_err("must fail");
    assert!(format!("{err}").contains("authority_config"));
}

#[test]
fn resolves_relative_paths_against_config_file() {
    let dir = tempfile::tempdir().expect("dir");
    let cfg_path = dir.path().join("firma-stack.toml");
    std::fs::write(
        &cfg_path,
        "authority_config = \"a.toml\"\nsidecar_config = \"s.toml\"\n",
    )
    .expect("write");
    let cfg = load_stack_config(&cfg_path).expect("parse");
    assert_eq!(cfg.authority_config, dir.path().join("a.toml"));
    assert_eq!(cfg.sidecar_config, dir.path().join("s.toml"));
}
