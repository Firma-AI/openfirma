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
use std::path::PathBuf;

use firma_run::sidecar::config::testing::{SynthesizeRequest, TemplateSource, synthesize};
use tempfile::TempDir;

fn read(path: &std::path::Path) -> toml::Value {
    let text = fs::read_to_string(path).expect("read synthesized");
    toml::from_str(&text).expect("parse synthesized")
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
        agent_id: "generic",
        session_id: "sess",
        explicit_template: None,
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: Some(&audit),
        monitor_mode: false,
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
[audit]
sink = "stdout"
"#,
    )
    .expect("write template");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let audit = tmp.path().join("audit.jsonl");
    synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: Some(&template),
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: Some(&audit),
        monitor_mode: false,
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
    let source = synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: None,
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("synthesize");
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
    assert_eq!(
        interceptor.get("mode").and_then(|v| v.as_str()),
        Some("unix_socket")
    );
    assert_eq!(
        interceptor.get("socket_path").and_then(|v| v.as_str()),
        Some(sock.display().to_string()).as_deref()
    );
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
fn explicit_template_overrides_interceptor_section_only() {
    let tmp = TempDir::new().expect("tmp");
    let template = tmp.path().join("template.toml");
    fs::write(
        &template,
        r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:9090"

[interceptor.https_mitm]
enabled = false

[mapping]
rules_path = "/etc/firma/mapping.toml"

[capability_seed]
paths = ["/etc/firma/cap.toml"]
"#,
    )
    .expect("write template");

    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let source = synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: Some(&template),
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
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
    assert_eq!(
        interceptor.get("mode").and_then(|v| v.as_str()),
        Some("unix_socket")
    );
    assert_eq!(
        interceptor.get("socket_path").and_then(|v| v.as_str()),
        Some(sock.display().to_string()).as_deref()
    );
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
fn priority_order_explicit_over_env_over_cwd() {
    let tmp = TempDir::new().expect("tmp");

    let explicit = tmp.path().join("explicit.toml");
    let env = tmp.path().join("env.toml");
    let cwd = tmp.path().join("cwd.toml");
    for path in [&explicit, &env, &cwd] {
        fs::write(path, "[interceptor]\nmode = \"http_proxy\"\n").expect("write");
    }

    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");

    let source = synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: Some(&explicit),
        env_template: Some(env.clone()),
        cwd_template: Some(cwd.clone()),
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Explicit(explicit));

    let source = synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: None,
        env_template: Some(env.clone()),
        cwd_template: Some(cwd.clone()),
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Env(env));

    let source = synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: None,
        env_template: None,
        cwd_template: Some(cwd.clone()),
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Cwd(cwd));
}

#[test]
fn relative_template_resource_paths_rebase_to_template_dir() {
    let tmp = TempDir::new().expect("tmp");
    let template_dir = tmp.path().join("operator-config");
    fs::create_dir_all(&template_dir).expect("mkdir template dir");
    let template = template_dir.join("firma.toml");
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
        agent_id: "generic",
        session_id: "sess",
        explicit_template: Some(&template),
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
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
fn nonexistent_template_paths_fall_through_to_minimal() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let source = synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: Some(&PathBuf::from("/does/not/exist/explicit.toml")),
        env_template: Some(PathBuf::from("/does/not/exist/env.toml")),
        cwd_template: Some(PathBuf::from("/does/not/exist/cwd.toml")),
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Minimal);
}

#[test]
fn monitor_mode_injects_mode_monitor_into_sidecar_section() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: None,
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: true,
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
    synthesize(SynthesizeRequest {
        agent_id: "generic",
        session_id: "sess",
        explicit_template: None,
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        listen_addr: None,
        out_path: &out,
        authority_url: None,
        authority_ca_cert: None,
        authority_pub_key: None,
        audit_fallback_path: None,
        monitor_mode: false,
    })
    .expect("synthesize");

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
