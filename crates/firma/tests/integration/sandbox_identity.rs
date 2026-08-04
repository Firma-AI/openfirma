use std::process::Command;

use firma_runtime_state::SandboxId;

#[test]
fn firma_run_rejects_preexisting_reserved_sandbox_id() {
    let sandbox_id = SandboxId::generate();
    let out = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["run", "--", "true"])
        .env("FIRMA_RUN_SANDBOX_ID", sandbox_id.to_string())
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
        .env("FIRMA_RUN_SANDBOX_ID", "sbx_2n1t201rmv88eb2sj4cn248g00")
        .output()
        .expect("spawn firma sidecar");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    insta::assert_snapshot!(stderr, @"[ERR]  invalid FIRMA_RUN_SANDBOX_ID: sandbox id must be backed by a UUID v7: `sbx_2n1t201rmv88eb2sj4cn248g00` is backed by a UUID v4");
    assert!(!stderr.contains("no firma.toml found"));
}
