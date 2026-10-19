//! Section extraction behavior through the public schema API.

use firma_config_loader::{CONFIG_FILE_NAME, FirmaConfig, load_section};
use firma_config_schema::{authority, run, sidecar};
use firma_test_helpers::toml_fence_after;
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
fn unknown_top_level_table_is_rejected() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(&path, "[other]\nkeep = true\n").expect("write config");

    let error = FirmaConfig::load(&path).expect_err("unknown table must fail");
    assert!(
        error.to_string().contains("unknown top-level key `other`"),
        "error: {error}"
    );
}

#[test]
fn removed_project_table_is_rejected() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join(CONFIG_FILE_NAME);
    fs::write(&path, "[project]\nagent = \"codex\"\n").expect("write config");

    let error = FirmaConfig::load(&path).expect_err("removed table must fail");
    assert!(
        error
            .to_string()
            .contains("unknown top-level key `project`"),
        "error: {error}"
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

#[test]
fn tracked_unified_config_examples_match_the_strict_schema() {
    let tmp = tempfile::tempdir().expect("tmpdir");

    for (name, toml) in [
        (
            "configuration-full-example",
            toml_fence_after(
                include_str!("../../../../docs/configuration.md"),
                "## Full Example",
            ),
        ),
        (
            "transport-unified-example",
            toml_fence_after(
                include_str!("../../../../docs/security/transport.md"),
                "Then wire the generated paths",
            ),
        ),
        (
            "mtls-authority-example",
            toml_fence_after(
                include_str!("../../../../docs/security/mtls-playbook.md"),
                "Set the paths in the Authority section",
            ),
        ),
        (
            "mtls-sidecar-example",
            toml_fence_after(
                include_str!("../../../../docs/security/mtls-playbook.md"),
                "Add the Sidecar client settings",
            ),
        ),
    ] {
        let toml = toml.unwrap_or_else(|| panic!("{name}: TOML fence after marker exists"));
        let path = tmp.path().join(format!("{name}.toml"));
        fs::write(&path, toml).expect("write documentation example");
        assert_unified_config_parses(&path);
    }

    let examples =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/firma-run");
    for path in [
        "local-command-governance/configs/base-profile.toml",
        "local/assets/firma_run.local.example.toml",
    ] {
        assert_unified_config_parses(&examples.join(path));
    }
    // Managed setup never configures local mapping files, so the managed
    // example carries no local `[authority]` section or `mapping_rules_paths`.
    assert!(
        assert_unified_config_parses(&examples.join("firma.managed.example.toml")).is_none(),
        "managed example must not configure a local [authority] section"
    );
}

/// Parses every unified section of `path` and returns its `[authority]` section.
fn assert_unified_config_parses(path: &std::path::Path) -> Option<authority::AuthorityConfig> {
    let config = FirmaConfig::load(path).expect("load unified config example");
    let _: Option<sidecar::SidecarConfig> = config
        .optional_section("sidecar")
        .expect("parse sidecar section");
    let _: Option<run::FileConfig> = config.optional_section("run").expect("parse run section");
    config
        .optional_section("authority")
        .expect("parse authority section")
}

/// Rendered example templates must load under the strict schema, and every
/// Authority they start must publish mapping inputs: the Authority rejects a
/// configuration without them, and Sidecars no longer read local mappings.
#[test]
fn tracked_config_templates_render_to_valid_authority_owned_mappings() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    for template in [
        "../../examples/firma-git-demo/config/firma.toml.tmpl",
        "../../examples/firma-git-demo/config/firma-issue.toml.tmpl",
    ] {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(template);
        let text = fs::read_to_string(&source).expect("read config template");
        let path = tmp.path().join(CONFIG_FILE_NAME);
        fs::write(&path, render_placeholders(&text)).expect("write rendered template");

        if let Some(authority) = assert_unified_config_parses(&path) {
            assert!(
                !authority.mapping_rules_paths.is_empty(),
                "{template} starts an Authority without mapping inputs"
            );
        }
    }
}

/// Replace every `{{NAME}}` template placeholder with a loopback address, which
/// is valid wherever the templates interpolate an address or a path.
fn render_placeholders(template: &str) -> String {
    let mut rendered = String::new();
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("{{") {
        let (_, remainder) = after.split_once("}}").expect("closed placeholder");
        rendered.push_str(before);
        rendered.push_str("127.0.0.1:1");
        rest = remainder;
    }
    rendered.push_str(rest);
    rendered
}
