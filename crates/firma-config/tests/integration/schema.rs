//! Section extraction behavior through the public schema API.

use firma_config::{FirmaConfig, load_section};
use fs_err as fs;

#[test]
fn extracts_named_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(&path, "[sidecar]\nfoo = 1\n[authority]\nbar = 2\n").expect("write config");
    let out = load_section(&path, "sidecar").expect("load section");
    let table: toml::Table = out.parse().expect("parse section");
    assert_eq!(table.get("foo").and_then(toml::Value::as_integer), Some(1));
    assert!(table.get("bar").is_none());
}

#[test]
fn nested_subtables_are_preserved() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(
        &path,
        "[sidecar.interceptor]\nmode = \"http_proxy\"\n[sidecar.authority]\nurl = \"http://x\"\n",
    )
    .expect("write config");
    let out = load_section(&path, "sidecar").expect("load section");
    let table: toml::Table = out.parse().expect("parse section");
    assert!(
        table
            .get("interceptor")
            .and_then(toml::Value::as_table)
            .is_some()
    );
    assert!(
        table
            .get("authority")
            .and_then(toml::Value::as_table)
            .is_some()
    );
}

#[test]
fn missing_section_is_an_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(&path, "[authority]\nbar = 2\n").expect("write config");
    let error = load_section(&path, "sidecar").expect_err("section should be missing");
    assert!(
        error.to_string().contains("sidecar"),
        "error names the section: {error}"
    );
}

#[test]
fn dotted_path_extracts_nested_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(
        &path,
        "[sidecar.policy]\ndir = \".\"\n[sidecar.authority]\nurl = \"https://x\"\n",
    )
    .expect("write config");
    let policy = load_section(&path, "sidecar.policy").expect("load policy section");
    let policy_table: toml::Table = policy.parse().expect("parse policy section");
    assert_eq!(
        policy_table.get("dir").and_then(toml::Value::as_str),
        Some(".")
    );
    let connect = load_section(&path, "sidecar.authority").expect("load authority section");
    let authority_table: toml::Table = connect.parse().expect("parse authority section");
    assert_eq!(
        authority_table.get("url").and_then(toml::Value::as_str),
        Some("https://x")
    );
}

#[test]
fn dotted_path_missing_is_an_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(&path, "[sidecar.policy]\ndir = \".\"\n").expect("write config");
    let error = load_section(&path, "sidecar.authority").expect_err("section should be missing");
    assert!(
        error.to_string().contains("sidecar.authority"),
        "error: {error}"
    );
}

#[test]
fn firma_config_reuses_a_single_parse_for_multiple_sections() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("firma.toml");
    fs::write(&path, "[sidecar]\nfoo = 1\n[authority]\nbar = 2\n").expect("write config");

    let config = FirmaConfig::load(&path).expect("load config");
    let sidecar: toml::Table = config
        .section("sidecar")
        .expect("load sidecar section")
        .parse()
        .expect("parse sidecar section");
    let authority: toml::Table = config
        .section("authority")
        .expect("load authority section")
        .parse()
        .expect("parse authority section");

    assert_eq!(
        sidecar.get("foo").and_then(toml::Value::as_integer),
        Some(1)
    );
    assert_eq!(
        authority.get("bar").and_then(toml::Value::as_integer),
        Some(2)
    );
}
