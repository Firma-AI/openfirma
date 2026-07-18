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
