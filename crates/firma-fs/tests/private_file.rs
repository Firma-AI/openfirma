#![cfg(unix)]

use std::io;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn write_private_file_tightens_existing_file_permissions() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, b"old")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

    firma_fs::write_private_file(&path, b"new")?;

    let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(std::fs::read_to_string(&path)?, "new");
    Ok(())
}
