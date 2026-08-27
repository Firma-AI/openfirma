use firma_sidecar::config::{LocalExecConfigError, SidecarConfig, SidecarConfigError};

#[test]
fn sub_millisecond_local_exec_retry_after_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let tmpdir = tempfile::tempdir()?;
    let config_path = tmpdir.path().join("sidecar.toml");
    let socket_path = tmpdir.path().join("local-exec.sock");
    std::fs::write(
        &config_path,
        format!(
            r#"
[local_exec]
socket_path = '{}'
retry_after = "500us"
"#,
            socket_path.display()
        ),
    )?;

    let error = SidecarConfig::load_from_path(&config_path)
        .expect_err("a positive duration below the millisecond wire unit must fail");

    let SidecarConfigError::LocalExec(source) = &error else {
        return Err(format!("expected LocalExec error, got {error:?}").into());
    };
    assert_eq!(source, &LocalExecConfigError::RetryAfterBelowOneMillisecond);
    assert_eq!(
        error.to_string(),
        "local_exec: local_exec.retry_after must be at least 1ms"
    );
    Ok(())
}
