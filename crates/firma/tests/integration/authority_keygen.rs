//! Tests for `firma authority generate-key`.
//!
//! Covers the TOCTOU attack: the key file must be created
//! atomically with mode 0600, never passing through a world-readable
//! window. The pre-existing-file test asserts `create_new` semantics
//! prevent overwriting an attacker-planted file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

#[test]
fn generate_key_writes_both_files() {
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("auth.key");
    let pub_key = key.with_extension("pub");

    let output = generate_key(&key);
    assert!(
        output.status.success(),
        "generate-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(key.exists(), "secret key not created");
    assert!(pub_key.exists(), "public key not created");
}

#[cfg(unix)]
#[test]
fn generate_key_sets_unix_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("auth.key");
    let pub_key = key.with_extension("pub");

    let output = generate_key(&key);
    assert!(
        output.status.success(),
        "generate-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let secret_mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        secret_mode, 0o600,
        "secret key mode {secret_mode:o}, expected 0600 (TOCTOU regression)"
    );

    let pub_mode = std::fs::metadata(&pub_key).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        pub_mode, 0o644,
        "public key mode {pub_mode:o}, expected 0644"
    );
}

/// TOCTOU guard: if the target path already exists (e.g. an attacker
/// planted a symlink or a placeholder), `generate-key` must refuse
/// rather than overwrite. This pins `OpenOptions::create_new(true)`
/// behavior end-to-end.
#[test]
fn generate_key_refuses_to_overwrite_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("auth.key");
    let sentinel = b"pre-existing content that must not be overwritten";
    std::fs::write(&key, sentinel).unwrap();

    let output = generate_key(&key);
    assert!(
        !output.status.success(),
        "generate-key should fail when target exists; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let after = std::fs::read(&key).unwrap();
    assert_eq!(
        after, sentinel,
        "pre-existing file was modified despite create_new"
    );
}

/// Same guard for the `.pub` sibling: if `<path>.pub` exists, the
/// command must not silently clobber it.
#[test]
fn generate_key_refuses_to_overwrite_existing_pub_file() {
    let tmp = tempfile::tempdir().unwrap();
    let key = tmp.path().join("auth.key");
    let pub_key = key.with_extension("pub");
    let sentinel = b"pre-existing public key";
    std::fs::write(&pub_key, sentinel).unwrap();

    let output = generate_key(&key);
    assert!(
        !output.status.success(),
        "generate-key should fail when <path>.pub exists; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let after = std::fs::read(&pub_key).unwrap();
    assert_eq!(after, sentinel, "pre-existing .pub file was modified");
}

fn firma_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

fn generate_key(path: &std::path::Path) -> std::process::Output {
    std::process::Command::new(firma_bin())
        .args(["authority", "generate-key", "-o"])
        .arg(path)
        .output()
        .expect("spawn firma")
}
