//! Shared integration-test helpers.

use std::{ffi::OsString, path::Path};

use fs_err as fs;

/// Run `test` in an isolated process, using a temporary working tree.
///
/// This helper requires `cargo nextest` (`NEXTEST=1`) because it mutates
/// process-global state: it clears every `FIRMA_*` environment variable and
/// sets the process cwd. Nextest runs each test in its own process, so those
/// mutations cannot race with other tests.
///
/// The helper creates a temp directory, changes cwd to that temp root,
/// canonicalizes it, and passes the canonical root to `test`. The test body may
/// create additional directories and move cwd again; that remains safe under the
/// nextest process-isolation guard. The temp directory is removed after `test`
/// returns.
pub fn run_isolated(test: impl FnOnce(&Path)) {
    run_isolated_with_env(|_| Vec::new(), test);
}

/// Run `test` in an isolated process with root-derived environment variables.
///
/// This behaves like [`run_isolated`], then calls `env` with the canonical temp
/// root and sets each returned environment variable before running `test`.
/// Existing `FIRMA_*` variables are always cleared before any requested env vars
/// are set.
pub fn run_isolated_with_env(
    env: impl FnOnce(&Path) -> Vec<(OsString, OsString)>,
    test: impl FnOnce(&Path),
) {
    assert_eq!(
        std::env::var("NEXTEST").as_deref(),
        Ok("1"),
        "run_isolated mutates process cwd/env and must run under cargo nextest"
    );
    clear_firma_env();

    let tmp = tempfile::tempdir().expect("create isolated temporary directory");
    let root = fs::canonicalize(tmp.path()).expect("canonicalize isolated temporary directory");
    std::env::set_current_dir(&root).expect("set cwd to isolated temporary directory");
    set_env_vars(env(&root));

    test(&root);
}

#[expect(
    unsafe_code,
    reason = "nextest runs one process per test; env is cleared before test work starts"
)]
/// Clears all `FIRMA_*` environment variables for the current process.
fn clear_firma_env() {
    for (key, _) in std::env::vars_os() {
        let Some(key) = key.as_os_str().to_str() else {
            continue;
        };
        if key.starts_with("FIRMA_") {
            // SAFETY: guarded by `NEXTEST=1`; nextest executes each test in
            // its own process, and this helper runs before the test body.
            unsafe { std::env::remove_var(key) };
        }
    }
}

#[expect(
    unsafe_code,
    reason = "nextest runs one process per test; env is set before test work starts"
)]
fn set_env_vars(vars: Vec<(OsString, OsString)>) {
    for (key, value) in vars {
        // SAFETY: guarded by `NEXTEST=1`; nextest executes each test in its own
        // process, and this helper sets env before invoking the test body.
        unsafe { std::env::set_var(key, value) };
    }
}
