//! Black-box contract for `firma authority issue-client-cert`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::Path;
use std::process::{Command, Output};

const FIRMA_BIN: &str = env!("CARGO_BIN_EXE_firma");

#[test]
fn issue_client_cert_prints_canonical_allow_list_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("firma.toml");
    let ca_cert = temp.path().join("client-ca.crt");
    let ca_key = temp.path().join("client-ca.key");
    let ca_cert_toml = toml::Value::String(ca_cert.to_string_lossy().into_owned());
    let ca_key_toml = toml::Value::String(ca_key.to_string_lossy().into_owned());
    std::fs::write(
        &config,
        format!(
            r#"
[authority]
tls_cert_path = "server.crt"
tls_key_path = "server.key"
mtls_client_ca_cert_path = {ca_cert_toml}
mtls_client_ca_key_path = {ca_key_toml}
authorized_clients_path = "authorized_clients.toml"
"#,
        ),
    )
    .expect("write config");

    let generate = authority_command(&config)
        .args(["generate-client-ca", "--cert-out"])
        .arg(&ca_cert)
        .arg("--key-out")
        .arg(&ca_key)
        .output()
        .expect("generate client CA");
    assert_success(&generate, "generate-client-ca");

    let cases = [
        ("cn-only-sidecar", None, "cn-only-sidecar"),
        ("side\"car", None, "side\"car"),
        (
            "sidecar-common-name",
            Some("sidecar.example.internal"),
            "sidecar.example.internal",
        ),
    ];
    for (index, (cn, san, expected_identity)) in cases.into_iter().enumerate() {
        let cert_out = temp.path().join(format!("client-{index}.crt"));
        let key_out = temp.path().join(format!("client-{index}.key"));
        let mut command = authority_command(&config);
        command
            .args(["issue-client-cert", "--cn", cn, "--cert-out"])
            .arg(&cert_out)
            .arg("--key-out")
            .arg(&key_out);
        if let Some(san) = san {
            command.arg("--san").arg(san);
        }

        let output = command.output().expect("issue client certificate");
        assert_success(&output, "issue-client-cert");
        assert!(cert_out.is_file(), "client certificate was not written");
        assert!(key_out.is_file(), "client key was not written");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let snippet_start = stdout
            .find("[[clients]]")
            .unwrap_or_else(|| panic!("canonical allow-list table missing from stdout: {stdout}"));
        let snippet = &stdout[snippet_start..];
        let parsed: toml::Value = toml::from_str(snippet)
            .unwrap_or_else(|error| panic!("printed allow-list entry is invalid TOML: {error}"));
        assert!(
            parsed
                .get("clients")
                .and_then(toml::Value::as_array)
                .and_then(|clients| clients.first())
                .and_then(|client| client.get("identity"))
                .and_then(toml::Value::as_str)
                == Some(expected_identity),
            "printed allow-list identity does not match selected certificate identity: {snippet}"
        );
        assert!(
            !stdout.contains("[[authorized]]")
                && !stdout.contains("\n  cn =")
                && !stdout.contains("\n  san ="),
            "stdout exposed a noncanonical allow-list field: {stdout}"
        );
    }
}

fn authority_command(config: &Path) -> Command {
    let mut command = Command::new(FIRMA_BIN);
    command
        .arg("authority")
        .arg("--config")
        .arg(config)
        .env_remove("FIRMA_CONFIG")
        .env_remove("FIRMA_AUTHORITY_TLS_CERT_PATH")
        .env_remove("FIRMA_AUTHORITY_TLS_KEY_PATH")
        .env_remove("FIRMA_AUTHORITY_MTLS_CLIENT_CA_CERT_PATH")
        .env_remove("FIRMA_AUTHORITY_MTLS_CLIENT_CA_KEY_PATH")
        .env_remove("FIRMA_AUTHORITY_AUTHORIZED_CLIENTS_PATH")
        .env("FIRMA_LOG_FILTER", "off");
    command
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
