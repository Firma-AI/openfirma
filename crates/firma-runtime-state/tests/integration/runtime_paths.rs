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

/// Returns a root that is already absolute on every supported platform.
///
/// A POSIX-style `/name` is drive-relative on Windows, so resolution prepends
/// the current drive. Tests about precedence would then assert the runner's
/// working directory instead of the rule under test.
fn absolute_root(name: &str) -> PathBuf {
    #[cfg(unix)]
    let root = PathBuf::from(format!("/{name}"));
    #[cfg(windows)]
    let root = PathBuf::from(format!(r"C:\{name}"));
    root
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
    let explicit = absolute_root("explicit");
    let state_dir = absolute_root("custom-state");
    let layout = resolve(
        Some(explicit.clone()),
        Some(&state_dir.to_string_lossy()),
        Some("/run/user/1000"),
        Some(r"C:\AppData"),
        Some(r"C:\Temp"),
        1000,
    );
    assert_eq!(layout.root(), explicit);
}

#[test]
fn firma_state_dir_overrides_platform_environment() {
    let state_dir = absolute_root("custom-state");
    let layout = resolve(
        None,
        Some(&state_dir.to_string_lossy()),
        Some("/run/user/1000"),
        Some(r"C:\AppData"),
        Some(r"C:\Temp"),
        1000,
    );
    assert_eq!(layout.root(), state_dir);
}

/// Consumers hand runtime paths to processes that resolve them elsewhere:
/// bubblewrap resolves bind targets against its own root, and the trust
/// environment given to a wrapped process is read from the sandbox working
/// directory. A relative root must not survive resolution.
#[test]
fn relative_firma_state_dir_resolves_against_the_working_directory() {
    let cwd = std::env::current_dir().expect("resolve working directory");
    let layout = resolve(None, Some(".firma-state"), None, None, None, 1000);
    assert_eq!(layout.root(), cwd.join(".firma-state"));
}

/// The platform branches read environment variables, which are as
/// operator-supplied as the explicit inputs. A relative one must not survive
/// either, or it reaches bubblewrap as a bind target it cannot create.
#[test]
#[cfg(unix)]
fn relative_xdg_runtime_dir_resolves_against_the_working_directory() {
    let cwd = std::env::current_dir().expect("resolve working directory");
    let layout = resolve(None, None, Some("relative-runtime"), None, None, 1000);
    assert_eq!(layout.root(), cwd.join("relative-runtime").join("firma"));
}

#[test]
#[cfg(windows)]
fn relative_local_app_data_resolves_against_the_working_directory() {
    let cwd = std::env::current_dir().expect("resolve working directory");
    let layout = resolve(None, None, None, Some(r"relative-appdata"), None, 1000);
    assert_eq!(
        layout.root(),
        cwd.join("relative-appdata").join("firma").join("runtime")
    );
}

#[test]
#[cfg(windows)]
fn relative_temp_resolves_against_the_working_directory() {
    let cwd = std::env::current_dir().expect("resolve working directory");
    let layout = resolve(None, None, None, None, Some(r"relative-temp"), 1000);
    assert_eq!(layout.root(), cwd.join("relative-temp").join("firma"));
}

#[test]
fn relative_explicit_root_resolves_against_the_working_directory() {
    let cwd = std::env::current_dir().expect("resolve working directory");
    let layout = resolve(
        Some(PathBuf::from("relative-state")),
        None,
        None,
        None,
        None,
        1000,
    );
    assert_eq!(layout.root(), cwd.join("relative-state"));
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
    let run_entry = layout.run_entry_layout(&sandbox_id);
    assert_eq!(
        run_entry.root(),
        base.join("run").join(sandbox_id.to_string())
    );
    assert_eq!(
        run_entry.sidecar_socket(),
        run_entry.root().join("sidecar.sock")
    );
    assert_eq!(
        run_entry.sidecar_config(),
        run_entry.root().join("sidecar.toml")
    );
    assert_eq!(
        run_entry.sidecar_pid(),
        run_entry.root().join("sidecar.pid")
    );
    assert_eq!(
        run_entry.sidecar_metadata(),
        run_entry.root().join("metadata.toml")
    );
    // The Sidecar writes this material and firma-run reads it back, so the
    // exact file names are a cross-crate contract.
    assert_eq!(run_entry.ca_dir(), run_entry.root().join("firma-ca"));
    assert_eq!(run_entry.ca_cert(), run_entry.ca_dir().join("firma-ca.crt"));
    assert_eq!(
        run_entry.ca_bundle(),
        run_entry.ca_dir().join("firma-ca-bundle.crt")
    );
    assert_eq!(run_entry.ca_key(), run_entry.ca_dir().join("firma-ca.key"));
    assert_eq!(
        layout.capability_seed(&sandbox_id),
        base.join("capabilities").join(format!("{sandbox_id}.toml"))
    );
    assert_eq!(layout.audit_log(), base.join("audit.jsonl"));
    assert_eq!(layout.sidecar_socket(), base.join("sidecar.sock"));
    assert_eq!(layout.session_state(), base.join("session-state.jsonl"));
}
