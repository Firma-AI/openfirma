//! End-to-end: a sectioned firma.toml resolves and the sidecar section
//! parses through `load_section`.

use firma_config_loader::{CONFIG_FILE_NAME, ConfigResolver, ConfigSource};
use fs_err as fs;
use std::assert_matches;

#[test]
fn explicit_flag_sectioned_file_round_trips() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        "[sidecar.policy]\ndir = \"x\"\n[authority]\nbar = 1\n",
    )
    .expect("write config");
    let resolved = ConfigResolver::default()
        .resolve_config(Some(&path))
        .expect("resolve config")
        .expect("config should be found");
    assert_eq!(resolved.source, ConfigSource::Flag);
    let body = resolved
        .config
        .raw_section("sidecar")
        .expect("load sidecar section");
    let table: toml::Table = body.parse().expect("parse sidecar section");
    assert_matches!(table.get("policy"), Some(_));
    assert_matches!(table.get("bar"), None);
}
