//! Tests for the sidecar TOML synthesis used by `firma run` autostart.
//!
//! Uses the white-box `testing` reflector to feed inputs directly into
//! the synthesizer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
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

#[test]
fn missing_template_writes_minimal_config() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let source = synthesize(SynthesizeRequest {
        explicit_template: None,
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        out_path: &out,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Minimal);
    let value = read(&out);
    let interceptor = value
        .as_table()
        .and_then(|t| t.get("interceptor"))
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
        explicit_template: Some(&template),
        env_template: None,
        cwd_template: None,
        socket_path: &sock,
        out_path: &out,
    })
    .expect("synthesize");

    assert_eq!(source, TemplateSource::Explicit(template));
    let value = read(&out);
    let root = value.as_table().expect("root table");

    let interceptor = root
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
    assert!(root.contains_key("mapping"));
    assert!(root.contains_key("capability_seed"));
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
        explicit_template: Some(&explicit),
        env_template: Some(env.clone()),
        cwd_template: Some(cwd.clone()),
        socket_path: &sock,
        out_path: &out,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Explicit(explicit.clone()));

    let source = synthesize(SynthesizeRequest {
        explicit_template: None,
        env_template: Some(env.clone()),
        cwd_template: Some(cwd.clone()),
        socket_path: &sock,
        out_path: &out,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Env(env));

    let source = synthesize(SynthesizeRequest {
        explicit_template: None,
        env_template: None,
        cwd_template: Some(cwd.clone()),
        socket_path: &sock,
        out_path: &out,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Cwd(cwd));
}

#[test]
fn nonexistent_template_paths_fall_through_to_minimal() {
    let tmp = TempDir::new().expect("tmp");
    let out = tmp.path().join("sidecar.toml");
    let sock = tmp.path().join("sidecar.sock");
    let source = synthesize(SynthesizeRequest {
        explicit_template: Some(&PathBuf::from("/does/not/exist/explicit.toml")),
        env_template: Some(PathBuf::from("/does/not/exist/env.toml")),
        cwd_template: Some(PathBuf::from("/does/not/exist/cwd.toml")),
        socket_path: &sock,
        out_path: &out,
    })
    .expect("synthesize");
    assert_eq!(source, TemplateSource::Minimal);
}
