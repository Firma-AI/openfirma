//! Presence rule every consumer of a state-directory default shares.

#![allow(
    clippy::expect_used,
    reason = "integration-test setup uses expect to fail fast on filesystem errors"
)]

use firma_runtime_state::is_material_present;

#[test]
fn a_readable_file_is_present() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("authority.pub");
    std::fs::write(&path, "material").expect("write material");

    assert!(is_material_present(&path));
}

#[test]
fn a_path_nobody_wrote_is_absent() {
    let tmp = tempfile::tempdir().expect("tempdir");

    assert!(!is_material_present(&tmp.path().join("authority.pub")));
}

/// A directory standing where the material belongs is not something a consumer
/// can read, so adopting the position would only move the failure later.
#[test]
fn a_directory_in_the_materials_place_is_absent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("authority.pub");
    std::fs::create_dir(&path).expect("create directory");

    assert!(!is_material_present(&path));
}

/// Material hidden behind a mode that blocks `stat` is reported as present, so
/// the component that opens it reports the permission error instead of the
/// consumer degrading to "no anchor configured". Root ignores the mode, so the
/// distinction is unobservable there.
#[cfg(unix)]
#[test]
fn material_that_cannot_be_stat_ed_is_present() {
    use std::os::unix::fs::PermissionsExt;

    if nix::unistd::Uid::current().is_root() {
        eprintln!("skipped: root bypasses the directory mode this case depends on");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let hidden = tmp.path().join("hidden");
    std::fs::create_dir(&hidden).expect("create directory");
    let path = hidden.join("authority.pub");
    std::fs::write(&path, "material").expect("write material");
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let present = is_material_present(&path);

    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700)).expect("restore");
    assert!(present);
}
