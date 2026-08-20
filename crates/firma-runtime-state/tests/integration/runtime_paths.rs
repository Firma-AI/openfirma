//! Resolver and path matrix for `RuntimeLayout`.

#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses expect to fail fast on resolver errors"
)]

use std::path::PathBuf;

use firma_runtime_state::RuntimeLayout;

fn resolve(
    flag: Option<PathBuf>,
    firma_state_dir: Option<&str>,
    xdg_runtime_dir: Option<&str>,
    local_app_data: Option<&str>,
    temp: Option<&str>,
    uid: u32,
) -> RuntimeLayout {
    RuntimeLayout::resolve_from(
        flag,
        firma_state_dir.map(str::to_string),
        xdg_runtime_dir.map(str::to_string),
        local_app_data.map(str::to_string),
        temp.map(str::to_string),
        uid,
    )
    .expect("resolve runtime layout")
}

#[test]
#[cfg(unix)]
fn unix_uses_xdg_runtime_dir_when_set() {
    let layout = resolve(None, None, Some("/run/user/1000"), None, None, 1000);
    assert_eq!(layout.root(), PathBuf::from("/run/user/1000/firma"));
}

#[test]
#[cfg(unix)]
fn unix_falls_back_to_tmp_when_xdg_runtime_dir_unset() {
    let layout = resolve(None, None, None, None, None, 1000);
    assert_eq!(layout.root(), PathBuf::from("/tmp/firma-1000"));
}

#[test]
#[cfg(unix)]
fn unix_ignores_empty_xdg_runtime_dir() {
    let layout = resolve(None, None, Some(""), None, None, 42);
    assert_eq!(layout.root(), PathBuf::from("/tmp/firma-42"));
}

#[test]
fn explicit_root_overrides_environment() {
    let layout = resolve(
        Some(PathBuf::from("/explicit")),
        Some("/custom/state"),
        Some("/run/user/1000"),
        Some(r"C:\AppData"),
        Some(r"C:\Temp"),
        1000,
    );
    assert_eq!(layout.root(), PathBuf::from("/explicit"));
}

#[test]
fn firma_state_dir_overrides_platform_environment() {
    let layout = resolve(
        None,
        Some("/custom/state"),
        Some("/run/user/1000"),
        Some(r"C:\AppData"),
        Some(r"C:\Temp"),
        1000,
    );
    assert_eq!(layout.root(), PathBuf::from("/custom/state"));
}

#[test]
#[cfg(windows)]
fn windows_uses_local_app_data() {
    let layout = resolve(None, None, None, Some(r"C:\Users\u\AppData\Local"), None, 0);
    assert_eq!(
        layout.root(),
        PathBuf::from(r"C:\Users\u\AppData\Local\firma\runtime")
    );
}

#[test]
fn derives_all_runtime_contract_paths_from_one_root() {
    let base = PathBuf::from("/run/user/1000/firma");
    let layout = RuntimeLayout::from_root(&base);
    let sandbox_id = firma_identifiers::SandboxId::generate();
    assert_eq!(layout.run_dir(), base.join("run"));
    assert_eq!(
        layout.run_entry(&sandbox_id),
        base.join("run").join(sandbox_id.to_string())
    );
    assert_eq!(
        layout.capability_seed(&sandbox_id),
        base.join("capabilities").join(format!("{sandbox_id}.toml"))
    );
    assert_eq!(layout.audit_log(), base.join("audit.jsonl"));
    assert_eq!(layout.sidecar_socket(), base.join("sidecar.sock"));
    assert_eq!(layout.session_state(), base.join("session-state.jsonl"));
}
