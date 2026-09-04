//! Tests for the sidecar TOML synthesis used by `firma run` autostart.
//!
//! Uses the white-box `testing` reflector to feed inputs directly into
//! the synthesizer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code: panics acceptable on test failure"
)]

use std::fs;
use std::path::Path;

use firma_config_loader::{AgentProfile, CONFIG_FILE_NAME};
use firma_core::SecretNameSource;
use firma_http::{Authority, Method};
use firma_run::sidecar::config::testing::{
    SynthesizeRequest, TemplateSource, resolve_template_sources, synthesize,
};
use firma_secret_provider::MatcherRule;
use firma_secret_provider::spec::http::{HttpIntegrationSpec, PathAndMatcher};
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::normalizer::{MappingTable, MatchResult};
use tempfile::TempDir;

fn read(path: &Path) -> toml::Value {
    let text = fs::read_to_string(path).expect("read synthesized");
    toml::from_str(&text).expect("parse synthesized")
}

fn synthesized_mapping_table(rules_path: &Path) -> MappingTable {
    let rules = fs::read_to_string(rules_path).expect("read mapping rules");
    let file = toml::from_str(&rules).expect("parse mapping rules");
    MappingTable::from_config(&file, &ActionClassRegistry::v0_1(), true).expect("mapping table")
}

/// Reads `[sidecar.audit]` from a synthesized config file.
fn audit_table(value: &toml::Value) -> &toml::value::Table {
    value
        .as_table()
        .and_then(|t| t.get("sidecar"))
        .and_then(|v| v.as_table())
        .and_then(|s| s.get("audit"))
        .and_then(|v| v.as_table())
        .expect("sidecar.audit table")
}

/// Default [`SynthesizeRequest`] for tests. Override specific fields with
/// struct-update syntax: `SynthesizeRequest { monitor_mode: true, ..req(&sock, &out) }`.
fn req<'a>(sock: &'a Path, out: &'a Path) -> SynthesizeRequest<'a> {
    SynthesizeRequest {
        agent_id: super::helper::agent_id(),
        execution_profile: AgentProfile::Generic,
        session_id: "sess",
        template: resolve_template_sources(None).expect("resolve Sidecar template"),
        socket_path: sock,
        listen_addr: None,
        out_path: out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        authority_credentials: None,
        capability_seed_path: None,
        audit_fallback_path: None,
        monitor_mode: false,
        http_secret_providers: &[],
    }
}

#[test]
fn minimal_template_defaults_audit_to_monitorable_file_sink() {
    // With no template, the synthesized per-run sidecar must default its audit
    // sink to a file at the shared state dir so `firma monitor` can tail it.
    // Otherwise the default `stdout` sink writes to the spawned sidecar's null
    // stdout and `firma monitor` shows nothing (FIR-193).
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let audit = tmp.path().join("audit.jsonl");
    synthesize(SynthesizeRequest {
        audit_fallback_path: Some(&audit),
        ..req(&sock, &out)
    })
    .expect("synthesize");

    let value = read(&out);
    let audit_tbl = audit_table(&value);
    assert_eq!(
        audit_tbl.get("sink").and_then(toml::Value::as_str),
        Some("file")
    );
    assert_eq!(
        audit_tbl.get("file_path").and_then(toml::Value::as_str),
        Some(audit.display().to_string()).as_deref()
    );
}

#[test]
fn explicit_audit_sink_is_not_overridden_by_fallback() {
    // An operator-configured audit sink must win over the fallback default.
    let tmp = TempDir::new().expect("tmp");
    let template = tmp.path().join("template.toml");
    fs::write(
        &template,
        r#"
[sidecar.audit]
sink = "stdout"
"#,
    )
    .expect("write template");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let audit = tmp.path().join("audit.jsonl");
    synthesize(SynthesizeRequest {
        template: resolve_template_sources(Some(&template)).expect("resolve Sidecar template"),
        audit_fallback_path: Some(&audit),
        ..req(&sock, &out)
    })
    .expect("synthesize");

    let value = read(&out);
    let audit_tbl = audit_table(&value);
    assert_eq!(
        audit_tbl.get("sink").and_then(toml::Value::as_str),
        Some("stdout"),
        "explicit stdout sink must be preserved"
    );
    assert!(
        audit_tbl.get("file_path").is_none(),
        "fallback must not inject file_path over an explicit sink"
    );
}

#[test]
fn missing_template_writes_minimal_config() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let source = synthesize(req(&sock, &out)).expect("synthesize");
    assert_eq!(source, TemplateSource::Minimal);
    let value = read(&out);
    let sidecar = value
        .as_table()
        .and_then(|t| t.get("sidecar"))
        .and_then(|v| v.as_table())
        .expect("sidecar table");
    let interceptor = sidecar
        .get("interceptor")
        .and_then(|v| v.as_table())
        .expect("interceptor table");
    #[cfg(unix)]
    {
        assert_eq!(
            interceptor.get("mode").and_then(|v| v.as_str()),
            Some("unix_socket")
        );
        assert_eq!(
            interceptor.get("socket_path").and_then(|v| v.as_str()),
            Some(sock.display().to_string()).as_deref()
        );
    }
    #[cfg(windows)]
    {
        assert_eq!(
            interceptor.get("mode").and_then(|v| v.as_str()),
            Some("http_proxy")
        );
        assert!(
            interceptor
                .get("listen_addr")
                .and_then(|v| v.as_str())
                .is_some(),
            "windows minimal config must have a listen_addr for http_proxy"
        );
    }
    let mapping = sidecar
        .get("mapping")
        .and_then(|v| v.as_table())
        .expect("mapping table");
    assert_eq!(
        mapping
            .get("default_protected")
            .and_then(toml::Value::as_bool),
        Some(true)
    );
}

#[test]
fn effective_capability_key_is_written_to_sidecar_authority_config() {
    let tmp = TempDir::new().expect("tmp");
    let template = tmp.path().join("template.toml");
    fs::write(
        &template,
        "[sidecar.authority]\npublic_key_path = \"template.pub\"\n",
    )
    .expect("write template");
    let effective_key = tmp.path().join("firmateam-workspace.pub");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");

    synthesize(SynthesizeRequest {
        template: resolve_template_sources(Some(&template)).expect("resolve Sidecar template"),
        authority_pub_key: Some(&effective_key),
        ..req(&sock, &out)
    })
    .expect("synthesize");

    let value = read(&out);
    let configured_key = value
        .get("sidecar")
        .and_then(|sidecar| sidecar.get("authority"))
        .and_then(|authority| authority.get("public_key_path"))
        .and_then(toml::Value::as_str);
    assert_eq!(
        configured_key,
        Some(effective_key.display().to_string()).as_deref()
    );
}

#[test]
fn sectioned_explicit_template_overrides_interceptor_section_only() {
    let tmp = TempDir::new().expect("tmp");
    let template = tmp.path().join("template.toml");
    fs::write(
        &template,
        r#"
[sidecar.interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"

[sidecar.interceptor.https_mitm]
enabled = false

[sidecar.mapping]
rules_path = "/etc/firma/mapping.toml"

[sidecar.capability_seed]
paths = ["/etc/firma/cap.toml"]
"#,
    )
    .expect("write template");

    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let source = synthesize(SynthesizeRequest {
        template: resolve_template_sources(Some(&template)).expect("resolve Sidecar template"),
        ..req(&sock, &out)
    })
    .expect("synthesize");

    assert_eq!(source, TemplateSource::Explicit(template));
    let value = read(&out);
    let root = value.as_table().expect("root table");
    let sidecar = root
        .get("sidecar")
        .and_then(|v| v.as_table())
        .expect("sidecar");

    let interceptor = sidecar
        .get("interceptor")
        .and_then(|v| v.as_table())
        .expect("interceptor");
    #[cfg(unix)]
    {
        assert_eq!(
            interceptor.get("mode").and_then(|v| v.as_str()),
            Some("unix_socket")
        );
        assert_eq!(
            interceptor.get("socket_path").and_then(|v| v.as_str()),
            Some(sock.display().to_string()).as_deref()
        );
    }
    #[cfg(windows)]
    {
        assert_eq!(
            interceptor.get("mode").and_then(|v| v.as_str()),
            Some("http_proxy")
        );
    }
    // listen_addr from template preserved verbatim — sidecar validator
    // tolerates extra keys, and this proves we did not wipe the table.
    assert_eq!(
        interceptor.get("listen_addr").and_then(|v| v.as_str()),
        Some("127.0.0.1:9090")
    );
    let mitm = interceptor
        .get("https_mitm")
        .and_then(|v| v.as_table())
        .expect("mitm");
    assert_eq!(
        mitm.get("enabled").and_then(toml::Value::as_bool),
        Some(false)
    );
    assert!(sidecar.contains_key("mapping"));
    assert!(sidecar.contains_key("capability_seed"));
}

#[test]
fn resolved_firma_toml_is_selected_over_minimal() {
    let tmp = TempDir::new().expect("tmp");

    let template = tmp.path().join("firma.toml");
    fs::write(&template, "[sidecar.interceptor]\nmode = \"http_proxy\"\n").expect("write");

    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");

    let source = synthesize(SynthesizeRequest {
        template: resolve_template_sources(Some(&template)).expect("resolve Sidecar template"),
        ..req(&sock, &out)
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Explicit(template));

    let source = synthesize(SynthesizeRequest {
        template: resolve_template_sources(None).expect("resolve Sidecar template"),
        ..req(&sock, &out)
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Minimal);
}

#[test]
fn flat_template_fails_without_writing() {
    let tmp = TempDir::new().expect("tmp");
    let template_path = tmp.path().join("template.toml");
    fs::write(&template_path, "[interceptor]\nmode = \"http_proxy\"\n")
        .expect("write flat template");
    let output_dir = tmp.path().join("output");
    let out = output_dir.join("sidecar.toml");
    let sock = output_dir.join("sidecar.sock");

    let error =
        resolve_template_sources(Some(&template_path)).expect_err("flat template must fail");
    match error {
        firma_run::error::RunError::ConfigParse { path, reason } => {
            assert_eq!(path, template_path);
            assert!(
                reason.contains("unknown top-level key `interceptor`"),
                "{reason}"
            );
        }
        other => panic!("unexpected error {other}"),
    }
    assert!(
        !output_dir.exists(),
        "template resolution wrote output artifacts"
    );
    assert!(!out.exists());
    assert!(!sock.exists());
}

#[test]
fn sectioned_template_with_superseded_field_fails_without_writing() {
    let tmp = TempDir::new().expect("tmp");
    let template_path = tmp.path().join("template.toml");
    fs::write(
        &template_path,
        "[sidecar.interceptor]\ndrain_timeout_secs = 30\n",
    )
    .expect("write invalid sectioned template");
    let output_dir = tmp.path().join("output");

    let error =
        resolve_template_sources(Some(&template_path)).expect_err("superseded field must fail");
    match error {
        firma_run::error::RunError::ConfigParse { path, reason } => {
            assert_eq!(path, template_path);
            assert!(
                reason.contains("unknown field `drain_timeout_secs`"),
                "{reason}"
            );
        }
        other => panic!("unexpected error {other}"),
    }
    assert!(!output_dir.exists(), "template resolution wrote artifacts");
}

#[test]
fn template_without_sidecar_section_fails_without_writing() {
    let tmp = TempDir::new().expect("tmp");
    let template_path = tmp.path().join("template.toml");
    fs::write(&template_path, "[run]\nprofile = \"generic\"\n")
        .expect("write template without Sidecar section");
    let output_dir = tmp.path().join("output");

    let error = resolve_template_sources(Some(&template_path))
        .expect_err("missing Sidecar section must fail");
    match error {
        firma_run::error::RunError::ConfigParse { path, reason } => {
            assert_eq!(path, template_path);
            assert!(
                reason.contains("missing required `[sidecar]` section"),
                "{reason}"
            );
        }
        other => panic!("unexpected error {other}"),
    }
    assert!(!output_dir.exists(), "template resolution wrote artifacts");
}

#[test]
fn relative_template_resource_paths_rebase_to_template_dir() {
    let tmp = TempDir::new().expect("tmp");
    let template_dir = tmp.path().join("operator-config");
    fs::create_dir_all(&template_dir).expect("mkdir template dir");
    let template = template_dir.join(CONFIG_FILE_NAME);
    // Touch sentinel files so the assertions key off real paths (the
    // rebase logic itself does not require them, but it documents that
    // the operator's config dir is where these resources actually live).
    fs::write(template_dir.join("audit.key"), b"pem").expect("audit key");
    fs::write(template_dir.join("mapping-rules.toml"), b"[[rules]]\n").expect("rules");
    let policies = template_dir.join("policies");
    fs::create_dir_all(&policies).expect("policies dir");

    // Use a platform-appropriate absolute path: Unix-style "/abs/..." is
    // NOT absolute on Windows (no drive prefix), so it would be rebased
    // instead of left untouched. Drive-prefixed paths are absolute on both.
    #[cfg(windows)]
    let (abs_keep, abs_seed) = ("C:/abs/keep.toml", "C:/abs/seed.toml");
    #[cfg(not(windows))]
    let (abs_keep, abs_seed) = ("/abs/keep.toml", "/abs/seed.toml");

    fs::write(
        &template,
        format!(
            r#"
[sidecar.audit]
signing_key_path = "audit.key"
file_path = "audit/events.jsonl"

[sidecar.policy]
dir = "policies"

[sidecar.mapping]
rules_path = "mapping-rules.toml"
rules_paths = ["extras/github.toml", "{abs_keep}"]

[sidecar.authority]
public_key_path = "keys/authority.pub"

[sidecar.capability_seed]
paths = ["seeds/dev.toml", "{abs_seed}"]
"#
        ),
    )
    .expect("write template");

    // Synthesize into a marker directory that is NOT under template_dir
    // so a wrong rebase would point at the wrong filesystem location.
    let marker = tmp.path().join("marker");
    fs::create_dir_all(&marker).expect("marker dir");
    let out = marker.join("sidecar.toml");
    let sock = marker.join("sidecar.sock");

    synthesize(SynthesizeRequest {
        template: resolve_template_sources(Some(&template)).expect("resolve Sidecar template"),
        ..req(&sock, &out)
    })
    .expect("synthesize");

    let value = read(&out);
    let sidecar = value
        .as_table()
        .and_then(|t| t.get("sidecar"))
        .and_then(|v| v.as_table())
        .expect("sidecar");

    let audit = sidecar
        .get("audit")
        .and_then(|v| v.as_table())
        .expect("audit");
    assert_eq!(
        audit.get("signing_key_path").and_then(|v| v.as_str()),
        Some(template_dir.join("audit.key").display().to_string()).as_deref()
    );
    assert_eq!(
        audit.get("file_path").and_then(|v| v.as_str()),
        Some(
            template_dir
                .join("audit/events.jsonl")
                .display()
                .to_string()
        )
        .as_deref()
    );

    let policy = sidecar
        .get("policy")
        .and_then(|v| v.as_table())
        .expect("policy");
    assert_eq!(
        policy.get("dir").and_then(|v| v.as_str()),
        Some(template_dir.join("policies").display().to_string()).as_deref()
    );

    let mapping = sidecar
        .get("mapping")
        .and_then(|v| v.as_table())
        .expect("mapping");
    assert_eq!(
        mapping.get("rules_path").and_then(|v| v.as_str()),
        Some(
            template_dir
                .join("mapping-rules.toml")
                .display()
                .to_string()
        )
        .as_deref()
    );
    let rules_paths = mapping
        .get("rules_paths")
        .and_then(|v| v.as_array())
        .expect("rules_paths array");
    assert_eq!(
        rules_paths
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            template_dir
                .join("extras/github.toml")
                .display()
                .to_string(),
            abs_keep.to_string()
        ]
    );

    let authority = sidecar
        .get("authority")
        .and_then(|v| v.as_table())
        .expect("authority");
    assert_eq!(
        authority.get("public_key_path").and_then(|v| v.as_str()),
        Some(
            template_dir
                .join("keys/authority.pub")
                .display()
                .to_string()
        )
        .as_deref()
    );

    let capability_seed = sidecar
        .get("capability_seed")
        .and_then(|v| v.as_table())
        .expect("capability_seed");
    let seed_paths = capability_seed
        .get("paths")
        .and_then(|v| v.as_array())
        .expect("paths array");
    assert_eq!(
        seed_paths
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            template_dir.join("seeds/dev.toml").display().to_string(),
            abs_seed.to_string()
        ]
    );
}

#[test]
fn nonexistent_template_fails() {
    let tmp = TempDir::new().expect("tmp");
    let missing = tmp.path().join("missing.toml");

    let error = resolve_template_sources(Some(&missing)).expect_err("missing template must fail");
    match error {
        firma_run::error::RunError::ConfigParse { path, reason } => {
            assert_eq!(path, missing);
            assert!(reason.starts_with("failed to read Sidecar template:"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn vscode_minimal_mapping_covers_github_sign_in_hosts() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    synthesize(SynthesizeRequest {
        execution_profile: AgentProfile::Vscode,
        listen_addr: Some("127.0.0.1:18080".parse().expect("listen addr")),
        ..req(&sock, &out)
    })
    .expect("synthesize");

    let value = read(&out);
    let bypass_hosts = value
        .get("sidecar")
        .and_then(toml::Value::as_table)
        .and_then(|sidecar| sidecar.get("interceptor"))
        .and_then(toml::Value::as_table)
        .and_then(|interceptor| interceptor.get("https_mitm"))
        .and_then(toml::Value::as_table)
        .and_then(|mitm| mitm.get("bypass_hosts"))
        .and_then(toml::Value::as_array)
        .expect("VS Code GitHub MITM bypass hosts");
    assert_eq!(
        bypass_hosts
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>(),
        ["github.com", "api.github.com", "uploads.github.com"]
    );

    let table = synthesized_mapping_table(&tmp.path().join("mapping-rules.toml"));
    for host in [
        Authority::from_static("github.com"),
        Authority::from_static("api.github.com"),
        Authority::from_static("vscode.dev"),
        Authority::from_static("insiders.vscode.dev"),
        Authority::from_static("default.exp-tas.com"),
        Authority::from_static("acme.ghe.com"),
        Authority::from_static("api.acme.ghe.com"),
        Authority::from_static("accounts.google.com"),
        Authority::from_static("ssl.gstatic.com"),
        Authority::from_static("avatars.githubusercontent.com"),
        Authority::from_static("appleid.apple.com"),
        Authority::from_static("idmsa.apple.com"),
        Authority::from_static("appleid.cdn-apple.com"),
    ] {
        match table.find_match(&Method::CONNECT, &host, "/") {
            MatchResult::Matched(rule) => {
                assert_eq!(rule.action_class, "communication.external.send", "{host}");
            }
            other => panic!("expected {host} to be mapped, got {other:?}"),
        }
    }
}

#[test]
fn monitor_mode_injects_mode_monitor_into_sidecar_section() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    synthesize(SynthesizeRequest {
        monitor_mode: true,
        ..req(&sock, &out)
    })
    .expect("synthesize");

    let value = read(&out);
    let sidecar = value
        .as_table()
        .and_then(|t| t.get("sidecar"))
        .and_then(|v| v.as_table())
        .expect("sidecar table");
    assert_eq!(
        sidecar.get("mode").and_then(toml::Value::as_str),
        Some("monitor"),
        "monitor_mode=true must inject mode = \"monitor\" into [sidecar]"
    );
}

#[test]
fn no_monitor_mode_does_not_inject_mode_field() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    synthesize(req(&sock, &out)).expect("synthesize");

    let value = read(&out);
    let sidecar = value
        .as_table()
        .and_then(|t| t.get("sidecar"))
        .and_then(|v| v.as_table())
        .expect("sidecar table");
    assert!(
        sidecar.get("mode").is_none(),
        "monitor_mode=false must not inject a mode field"
    );
}

#[test]
fn http_secret_providers_are_mirrored_into_sidecar_config_and_load_back() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");

    let provider = HttpIntegrationSpec {
        provider_id: "aws-secrets-manager".to_string(),
        host: "secretsmanager.*.amazonaws.com".to_string(),
        matchers: vec![MatcherRule::SensitiveCommand(PathAndMatcher {
            path: None,
            matcher: firma_core::SecretMatcher::Json {
                record_path: "$".to_string(),
                value_path: "$.SecretString".to_string(),
                name: SecretNameSource::Path {
                    path: "$.Name".to_string(),
                },
                item_selector: None,
                domain_selector: None,
            },
        })],
    };

    synthesize(SynthesizeRequest {
        http_secret_providers: &[provider],
        ..req(&sock, &out)
    })
    .expect("synthesize");

    // The synthesized file must be loadable by the Sidecar's own config type,
    // with the entry intact end to end (not just structurally present as raw
    // TOML). Mirrors the real load path (`firma sidecar --config <path>`):
    // extract the `[sidecar]` section, then deserialize just that as
    // `SidecarConfig` — `SidecarConfig::load_from_path` parses a file whose
    // top level *is* the sidecar config, not one wrapped in `[sidecar]`.
    let value = read(&out);
    let sidecar_section = value.get("sidecar").expect("sidecar section").clone();
    let loaded: firma_config_schema::sidecar::SidecarConfig = sidecar_section
        .try_into()
        .expect("synthesized sidecar section must load");
    assert_eq!(loaded.http_secret_providers.len(), 1);
    let spec = &loaded.http_secret_providers[0];
    assert_eq!(spec.provider_id, "aws-secrets-manager");
    assert_eq!(spec.host, "secretsmanager.*.amazonaws.com");
}

#[test]
fn empty_http_secret_providers_omits_the_field() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    synthesize(req(&sock, &out)).expect("synthesize");

    let value = read(&out);
    let sidecar = value
        .as_table()
        .and_then(|t| t.get("sidecar"))
        .and_then(|v| v.as_table())
        .expect("sidecar table");
    assert!(
        sidecar.get("http_secret_providers").is_none(),
        "no HTTP providers configured must not inject an empty array field"
    );
}
