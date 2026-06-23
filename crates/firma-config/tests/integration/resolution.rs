//! End-to-end: a sectioned firma.toml resolves and the sidecar section
//! parses through `load_section`.

use firma_config::{ConfigSource, SystemDirs};
use fs_err as fs;

#[test]
fn explicit_flag_sectioned_file_round_trips() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(
        &path,
        "[sidecar.policy]\ndir = \"x\"\n[authority]\nbar = 1\n",
    )
    .expect("write config");
    let resolved = SystemDirs::default()
        .resolve_config(Some(&path))
        .expect("resolve config")
        .expect("config should be found");
    assert_eq!(resolved.source, ConfigSource::Flag);
    let body = resolved
        .config
        .section("sidecar")
        .expect("load sidecar section");
    let table: toml::Table = body.parse().expect("parse sidecar section");
    assert!(table.get("policy").is_some());
    assert!(table.get("bar").is_none());
}
