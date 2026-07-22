//! Section extraction behavior through the public schema API.

use firma_config_loader::{CONFIG_FILE_NAME, FirmaConfig, load_section};
use fs_err as fs;
use serde::Deserialize;
use std::assert_matches;

#[test]
fn extracts_named_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r"[sidecar]
          foo = 1
          [authority]
          bar = 2
        ",
    )
    .expect("write config");
    let out = load_section(&path, "sidecar").expect("load section");
    let table: toml::Table = out.parse().expect("parse section");
    assert_eq!(table.get("foo").and_then(toml::Value::as_integer), Some(1));
    assert_matches!(table.get("bar"), None);
}

#[test]
fn nested_subtables_are_preserved() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r#"[sidecar.interceptor]
           mode = "http_proxy"
           [sidecar.authority]
           url = "http://x"
        "#,
    )
    .expect("write config");
    let out = load_section(&path, "sidecar").expect("load section");
    let table: toml::Table = out.parse().expect("parse section");
    assert_matches!(
        table.get("interceptor").and_then(toml::Value::as_table),
        Some(_)
    );
    assert_matches!(
        table.get("authority").and_then(toml::Value::as_table),
        Some(_)
    );
}

#[test]
fn missing_section_is_an_error() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r"[authority]
          bar = 2
        ",
    )
    .expect("write config");
    let error = load_section(&path, "sidecar").expect_err("section should be missing");
    assert!(
        error.to_string().contains("sidecar"),
        "error names the section: {error}"
    );
}

#[test]
fn dotted_path_extracts_nested_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r#"[sidecar.policy]
           dir = "."
           [sidecar.authority]
           url = "https://x"
        "#,
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
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r#"[sidecar.policy]
           dir = "."
        "#,
    )
    .expect("write config");
    let error = load_section(&path, "sidecar.authority").expect_err("section should be missing");
    assert!(
        error.to_string().contains("sidecar.authority"),
        "error: {error}"
    );
}

#[derive(Debug, Deserialize)]
struct Probe {
    listen_addr: String,
}

#[test]
fn section_reads_a_typed_section_without_a_string_round_trip() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r#"[authority]
           listen_addr = "127.0.0.1:50051"
        "#,
    )
    .expect("write config");
    let config = FirmaConfig::load(&path).expect("load config");
    let probe: Probe = config.section("authority").expect("deserialize section");
    assert_eq!(probe.listen_addr, "127.0.0.1:50051");
}

#[test]
fn section_rejects_missing_required_field() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    // `listen_addr` is required by `Probe` but absent here.
    fs::write(
        &path,
        r"[authority]
          unexpected = 1
        ",
    )
    .expect("write config");
    let config = FirmaConfig::load(&path).expect("load config");
    let error = config
        .section::<Probe>("authority")
        .expect_err("missing required field must error");
    assert!(
        error.to_string().contains("invalid `[authority]` section"),
        "error: {error}"
    );
}

#[test]
fn optional_section_reads_a_present_typed_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r#"[authority]
           listen_addr = "127.0.0.1:50051"
        "#,
    )
    .expect("write config");
    let config = FirmaConfig::load(&path).expect("load config");
    let probe = config
        .optional_section::<Probe>("authority")
        .expect("deserialize section");
    let probe = probe.expect("authority section exists");
    assert_eq!(probe.listen_addr, "127.0.0.1:50051");
}

#[test]
fn optional_section_returns_none_for_missing_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(
        &path,
        r#"[sidecar]
           listen_addr = "127.0.0.1:50051"
        "#,
    )
    .expect("write config");
    let config = FirmaConfig::load(&path).expect("load config");
    let probe = config
        .optional_section::<Probe>("authority")
        .expect("missing optional section is not an error");
    assert_matches!(probe, None);
}

#[test]
fn optional_section_rejects_present_non_table_section() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(&path, r#"authority = "not-a-table""#).expect("write config");
    let config = FirmaConfig::load(&path).expect("load config");
    let error = config
        .optional_section::<Probe>("authority")
        .expect_err("present non-table section must error");
    assert!(
        error
            .to_string()
            .contains("invalid `[authority]` section: expected table"),
        "error: {error}"
    );
}
