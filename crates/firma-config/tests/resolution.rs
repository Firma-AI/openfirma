//! End-to-end: a sectioned firma.toml resolves and the sidecar section
//! parses through `load_section`.

#![allow(clippy::unwrap_used, clippy::panic)]

use firma_config::{ConfigSource, SystemDirs, load_section, resolve_config};
use tempfile::tempdir;

#[test]
fn explicit_flag_sectioned_file_round_trips() {
    let tmp = tempdir().unwrap();
    let p = tmp.path().join("firma.toml");
    std::fs::write(&p, "[sidecar.policy]\ndir = \"x\"\n[authority]\nbar = 1\n").unwrap();
    let r = resolve_config("sidecar", Some(&p), &SystemDirs).unwrap();
    assert_eq!(r.source, ConfigSource::Flag);
    let body = load_section(&r.config_file, "sidecar").unwrap();
    let t: toml::Table = body.parse().unwrap();
    assert!(t.get("policy").is_some());
    assert!(t.get("bar").is_none());
}
