use std::process::Command;

#[test]
fn firma_run_rejects_preexisting_reserved_sandbox_id() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["run", "--", "true"])
        .env(
            "FIRMA_RUN_SANDBOX_ID",
            "01900000-0000-7000-8000-000000000001",
        )
        .output()
        .expect("spawn firma run");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("reserved for internal child propagation"),
        "unexpected diagnostic: {stderr}"
    );
}

#[test]
fn firma_run_rejects_empty_reserved_sandbox_id() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["run", "--", "true"])
        .env("FIRMA_RUN_SANDBOX_ID", "")
        .output()
        .expect("spawn firma run");

    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("reserved for internal child propagation")
    );
}

#[test]
fn standalone_sidecar_rejects_non_v7_propagated_id_before_config_discovery() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .arg("sidecar")
        .env(
            "FIRMA_RUN_SANDBOX_ID",
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .output()
        .expect("spawn firma sidecar");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid FIRMA_RUN_SANDBOX_ID") && stderr.contains("UUID v7"),
        "unexpected diagnostic: {stderr}"
    );
    assert!(!stderr.contains("no firma.toml found"));
}

#[test]
fn standalone_sidecar_rejects_empty_propagated_id_before_config_discovery() {
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .arg("sidecar")
        .env("FIRMA_RUN_SANDBOX_ID", "")
        .output()
        .expect("spawn firma sidecar");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid FIRMA_RUN_SANDBOX_ID") && stderr.contains("UUID v7"),
        "unexpected diagnostic: {stderr}"
    );
    assert!(!stderr.contains("no firma.toml found"));
}
