//! Parsing of the host mount table that decides the bwrap sandbox procfs seal.

use std::path::Path;

use firma_run::backend::linux_bwrap::mount::HostProcfsMounts;
use firma_run::error::RunError;

#[test]
fn collects_every_procfs_mount_point() {
    // Mount points are escaped by the kernel, and a bind of `/proc` elsewhere
    // is a second procfs instance the seal must know about.
    let mountinfo = concat!(
        "23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw\n",
        "24 28 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n",
        "41 28 0:22 / /mnt/host\\040copy/proc rw,relatime - proc proc rw\n",
    );

    let mounts = HostProcfsMounts::from_mountinfo(mountinfo).expect("parse mountinfo");

    assert!(mounts.covers(Path::new("/proc/1/root")));
    assert!(mounts.covers(Path::new("/mnt/host copy/proc")));
    assert!(!mounts.covers(Path::new("/sys")));
    assert!(
        !mounts.covers(Path::new("/procfs-lookalike")),
        "prefix matching must respect path components"
    );
}

#[test]
fn fails_closed_on_a_malformed_mount_table() {
    // An unparseable table means the procfs set is unknown, and an unknown set
    // cannot be sealed.
    let error = HostProcfsMounts::from_mountinfo("23 28 0:22 / /proc rw,relatime\n")
        .expect_err("a line without a filesystem type must fail the launch");

    std::assert_matches!(
        &error,
        RunError::Backend { backend, .. } if backend == "bwrap"
    );
    insta::assert_snapshot!(
        error.to_string(),
        @"backend error (bwrap): failed to parse /proc/self/mountinfo line '23 28 0:22 / /proc rw,relatime'"
    );
}
