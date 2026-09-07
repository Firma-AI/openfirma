//! CA material failures surface synchronously from interceptor startup.
//!
//! MITM CA material lives at a fixed location under `[sidecar.ca].dir`. When
//! that directory cannot be created, the Sidecar must fail startup and name the
//! directory, rather than bind a port that can never complete a handshake.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use firma_runtime_state::RuntimeLayout;
use firma_sidecar::config::SidecarConfig;
use firma_sidecar::handler::RequestHandler;
use firma_sidecar::interceptor::InterceptorError;
use firma_sidecar::startup::{build_connector_registry, build_pipeline_runtime, spawn_interceptor};
use tokio_util::sync::CancellationToken;

/// Writes a minimal MITM-enabled proxy configuration whose CA directory is
/// `ca_dir`.
fn write_config(dir: &Path, ca_dir: &Path) -> anyhow::Result<SidecarConfig> {
    let rules_path = dir.join("mapping-rules.toml");
    fs::write(
        &rules_path,
        r#"
[[rules]]
method = "GET"
host = "example.com"
path = "/"
action_class = "communication.external.send"
"#,
    )?;
    let config_path = dir.join("firma.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[interceptor]
mode = "http_proxy"
listen_addr = "127.0.0.1:0"

[interceptor.https_mitm]
enabled = true
intercept_hosts = ["api.openai.com"]

[mapping]
rules_path = '{}'
default_protected = false

[ca]
dir = '{}'
"#,
            rules_path.display(),
            ca_dir.display()
        ),
    )?;
    SidecarConfig::load_from_path(&config_path).map_err(anyhow::Error::msg)
}

#[tokio::test]
async fn unusable_ca_directory_fails_interceptor_startup() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    // A regular file cannot hold a directory, so creating the CA directory
    // beneath it fails for reasons the Sidecar cannot repair.
    let blocker = temp.path().join("blocker");
    fs::write(&blocker, b"not a directory")?;
    let ca_dir = blocker.join("firma-ca");

    let config = write_config(temp.path(), &ca_dir)?;
    let runtime_layout = RuntimeLayout::from_root(temp.path());
    let runtime = build_pipeline_runtime(&runtime_layout, &config)?;
    let connectors = build_connector_registry(&config.connector)?;
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(1);
    let handler = Arc::new(RequestHandler::new(runtime.pipeline, connectors, audit_tx));

    let error = spawn_interceptor(&runtime_layout, &config, handler, CancellationToken::new())
        .err()
        .expect("unusable CA directory must fail startup");

    let interceptor_error = error
        .downcast_ref::<InterceptorError>()
        .expect("CA failure must surface as an interceptor error");
    let InterceptorError::ServerError(detail) = interceptor_error else {
        panic!("expected a server error, got: {interceptor_error}");
    };
    assert!(
        detail.starts_with(&format!(
            "failed to create MITM CA directory {}",
            ca_dir.display()
        )),
        "error must name the CA directory, got: {detail}"
    );
    Ok(())
}
