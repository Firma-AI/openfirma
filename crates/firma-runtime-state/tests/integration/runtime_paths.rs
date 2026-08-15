//! Resolver matrix for `firma_runtime_state::runtime_paths`.

use std::path::PathBuf;

use firma_runtime_state::runtime_paths::{
    capabilities_dir_from, capability_seed_path, default_runtime_dir_from, run_dir_from,
    run_entry_from,
};

#[test]
#[cfg(unix)]
fn unix_uses_xdg_runtime_dir_when_set() {
    let out = default_runtime_dir_from(Some("/run/user/1000".into()), None, None, 1000);
    assert_eq!(out, PathBuf::from("/run/user/1000/firma"));
}

#[test]
#[cfg(unix)]
fn unix_falls_back_to_tmp_when_xdg_runtime_dir_unset() {
    let out = default_runtime_dir_from(None, None, None, 1000);
    assert_eq!(out, PathBuf::from("/tmp/firma-1000"));
}

#[test]
#[cfg(unix)]
fn unix_ignores_empty_xdg_runtime_dir() {
    let out = default_runtime_dir_from(Some(String::new()), None, None, 42);
    assert_eq!(out, PathBuf::from("/tmp/firma-42"));
}

#[test]
fn firma_state_dir_overrides_all_platforms() {
    let out = default_runtime_dir_from(
        Some("/run/user/1000".into()),
        Some("/custom/state".into()),
        Some(r"C:\AppData".into()),
        1000,
    );
    assert_eq!(out, PathBuf::from("/custom/state"));
}

#[test]
#[cfg(windows)]
fn windows_uses_local_app_data() {
    let out = default_runtime_dir_from(None, None, Some(r"C:\Users\u\AppData\Local".into()), 0);
    assert_eq!(
        out,
        PathBuf::from(r"C:\Users\u\AppData\Local\firma\runtime")
    );
}

#[test]
fn run_dir_appends_run_segment() {
    let base = PathBuf::from("/run/user/1000/firma");
    assert_eq!(
        run_dir_from(&base),
        PathBuf::from("/run/user/1000/firma/run")
    );
}

#[test]
fn run_entry_joins_sandbox_id() {
    let base = PathBuf::from("/run/user/1000/firma");
    let sandbox_id = firma_identifiers::SandboxId::generate();
    assert_eq!(
        run_entry_from(&base, &sandbox_id),
        base.join("run").join(sandbox_id.to_string())
    );
}

#[test]
fn capabilities_dir_is_runtime_subdir() {
    let dir = capabilities_dir_from(std::path::Path::new("/run/firma"));
    assert_eq!(dir, std::path::PathBuf::from("/run/firma/capabilities"));
}

#[test]
fn capability_seed_path_uses_only_the_validated_id_as_filename() {
    let sandbox_id = firma_identifiers::SandboxId::generate();
    let path = capability_seed_path(&sandbox_id);
    let expected_filename = format!("{sandbox_id}.toml");
    assert_eq!(
        path.file_name().and_then(std::ffi::OsStr::to_str),
        Some(expected_filename.as_str())
    );
    assert_eq!(
        path.parent()
            .and_then(std::path::Path::file_name)
            .and_then(std::ffi::OsStr::to_str),
        Some("capabilities")
    );
}
