#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

fn assert_file_contents(path: &std::path::Path, expected: &str) -> io::Result<()> {
    assert_eq!(std::fs::read_to_string(path)?, expected);
    Ok(())
}

fn normalize_error_path(error: &str, path: &Path) -> String {
    let normalized = error.replace(&path.display().to_string(), "<path>");
    match normalized.rsplit_once(": ") {
        Some((prefix, _)) => format!("{prefix}: <os_error>"),
        None => "<os_error>".to_string(),
    }
}

#[test]
fn write_private_file_creates_new_file_with_private_mode() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("secret.txt");

    firma_fs::write_private_file(&path, b"new")?;

    assert_file_contents(&path, "new")?;
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    Ok(())
}

#[test]
fn write_private_file_tightens_existing_file_permissions() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"old")?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

    firma_fs::write_private_file(&path, b"new")?;

    assert_file_contents(&path, "new")?;
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    Ok(())
}

#[test]
fn write_private_file_fails_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing").join("secret.txt");

    let error = firma_fs::write_private_file(&path, b"new").expect_err("missing parent");

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let rendered = normalize_error_path(&error.to_string(), &path);
    insta::assert_snapshot!(rendered, @"<os_error>");
}

#[test]
fn create_private_dir_all_creates_nested_directories() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("a").join("b").join("c");

    firma_fs::create_private_dir_all(&path).expect("create nested dir");

    assert!(path.is_dir());
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    Ok(())
}

#[test]
fn create_private_dir_all_tightens_existing_directory_permissions() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state");
    std::fs::create_dir(&path)?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;

    firma_fs::create_private_dir_all(&path).expect("reuse dir");

    assert!(path.is_dir());
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    Ok(())
}

#[test]
fn create_private_dir_all_returns_create_error_for_existing_file() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("occupied");
    std::fs::write(&path, b"file")?;

    let error = firma_fs::create_private_dir_all(&path).expect_err("existing file");

    let rendered = normalize_error_path(&error.to_string(), &path);
    insta::assert_snapshot!(rendered, @"failed to create <path>: <os_error>");
    Ok(())
}

#[test]
fn write_file_creates_or_truncates_with_requested_mode() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.toml");
    std::fs::write(&path, b"old")?;

    firma_fs::write_file(&path, b"new", 0o640).expect("write file");

    assert_file_contents(&path, "new")?;
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
    Ok(())
}

#[test]
fn write_file_returns_open_error_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing").join("config.toml");

    let error = firma_fs::write_file(&path, b"new", 0o640).expect_err("missing parent");

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let rendered = normalize_error_path(&error.to_string(), &path);
    insta::assert_snapshot!(rendered, @"open <path>: <os_error>");
}

#[test]
fn write_new_file_creates_new_file_with_requested_mode() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("authority.key");

    firma_fs::write_new_file(&path, b"new", 0o600).expect("create file");

    assert_file_contents(&path, "new")?;
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    Ok(())
}

#[test]
fn write_new_file_returns_already_exists_without_overwriting() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("authority.key");
    std::fs::write(&path, b"old")?;

    let error = firma_fs::write_new_file(&path, b"new", 0o600).expect_err("existing file");

    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

    let rendered = normalize_error_path(&error.to_string(), &path);
    insta::assert_snapshot!(rendered, @"create <path>: <os_error>");
    assert_file_contents(&path, "old")
}

#[test]
fn write_new_file_returns_not_found_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing").join("authority.key");

    let error = firma_fs::write_new_file(&path, b"new", 0o600).expect_err("missing parent");

    assert_eq!(error.kind(), io::ErrorKind::NotFound);

    let rendered = normalize_error_path(&error.to_string(), &path);
    insta::assert_snapshot!(rendered, @"create <path>: <os_error>");
}
