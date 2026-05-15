//! Tests for `firma stack init`.
//!
//! Verifies that scaffolded TOML configs are syntactically valid and that
//! `firma-stack` can load the generated `firma-stack.toml`. Regression guard
//! for Windows path serialization: backslash-bearing paths must not be
//! emitted into TOML basic strings (where `\t`, `\s`, etc. are invalid
//! escape sequences).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

use std::path::Path;
use std::process::Command;

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn run_init(config_dir: &Path, state_dir: &Path) {
    let output = firma()
        .args(["stack", "init", "--config-dir"])
        .arg(config_dir)
        .args(["--state-dir"])
        .arg(state_dir)
        .output()
        .expect("spawn firma stack init");
    assert!(
        output.status.success(),
        "stack init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn init_writes_parseable_configs() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    // All three TOML files must parse as TOML — the regression we are
    // guarding against is unescaped backslashes inside basic strings on
    // Windows (e.g. `state_dir = "C:\Users\..."` choking on `\U`).
    for name in ["firma-stack.toml", "authority.toml", "sidecar.toml"] {
        let path = config_dir.join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        toml::from_str::<toml::Value>(&text)
            .unwrap_or_else(|e| panic!("parse {}: {e}\n---\n{text}", path.display()));
    }

    // Deeper check: firma-stack's own loader must accept the file and
    // resolve the embedded paths.
    let stack_cfg_path = config_dir.join("firma-stack.toml");
    let cfg = firma_stack::load_stack_config(&stack_cfg_path)
        .unwrap_or_else(|e| panic!("load_stack_config({}): {e}", stack_cfg_path.display()));

    assert_eq!(
        cfg.state_dir.as_deref(),
        Some(state_dir.as_path()),
        "state_dir round-trip mismatch",
    );
    assert_eq!(cfg.authority_config, config_dir.join("authority.toml"));
    assert_eq!(cfg.sidecar_config, config_dir.join("sidecar.toml"));

    // The sidecar.toml emitted by init must pass `SidecarConfig`'s own
    // validation — regression guard for the case where the default
    // `InterceptorMode` flips (e.g. to `unix_socket` on Unix) and the
    // scaffolder still writes only `listen_addr`, which then fails
    // validation at sidecar startup with
    // `interceptor.socket_path is required when mode is unix_socket`.
    firma_sidecar::config::SidecarConfig::load_from_path(&cfg.sidecar_config)
        .unwrap_or_else(|e| panic!("sidecar.toml fails validation: {e}"));
}

#[test]
fn init_handles_relative_paths() {
    // Relative paths exercise the worst case of the Windows bug: the path
    // `..\test\state` parses as TOML `\t` (tab) + `est\state` which is
    // valid-but-wrong on Windows, while `..\state` would hit invalid `\s`.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let work = tmp.path().join("workdir");
    std::fs::create_dir_all(&work).unwrap();

    let output = firma()
        .current_dir(&work)
        .args([
            "stack",
            "init",
            "--config-dir",
            "../config",
            "--state-dir",
            "../state",
        ])
        .output()
        .expect("spawn firma stack init");
    assert!(
        output.status.success(),
        "stack init (relative) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stack_cfg_path = work.join("../config/firma-stack.toml");
    let cfg = firma_stack::load_stack_config(&stack_cfg_path).unwrap_or_else(|e| {
        let text = std::fs::read_to_string(&stack_cfg_path).unwrap_or_default();
        panic!(
            "load_stack_config({}): {e}\n---\n{text}",
            stack_cfg_path.display(),
        );
    });

    // Regression: when `--config-dir`/`--state-dir` are relative, the paths
    // written into firma-stack.toml must NOT be relative. Otherwise
    // `load_stack_config` re-joins them against the stack TOML's parent dir,
    // producing a doubled path (`..\config\..\config\authority.toml`) that
    // does not exist on disk.
    assert!(
        cfg.authority_config.is_absolute(),
        "authority_config must be absolute, got {}",
        cfg.authority_config.display(),
    );
    assert!(
        cfg.sidecar_config.is_absolute(),
        "sidecar_config must be absolute, got {}",
        cfg.sidecar_config.display(),
    );
    let state_dir = cfg.state_dir.as_deref().expect("state_dir set by init");
    assert!(
        state_dir.is_absolute(),
        "state_dir must be absolute, got {}",
        state_dir.display(),
    );

    // And the resolved paths must actually point to the scaffolded files.
    assert!(
        cfg.authority_config.is_file(),
        "authority_config does not exist on disk: {}",
        cfg.authority_config.display(),
    );
    assert!(
        cfg.sidecar_config.is_file(),
        "sidecar_config does not exist on disk: {}",
        cfg.sidecar_config.display(),
    );
    assert!(
        state_dir.is_dir(),
        "state_dir does not exist on disk: {}",
        state_dir.display(),
    );
}

#[cfg(unix)]
#[test]
fn init_writes_state_and_config_dirs_with_mode_0700() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = tempfile::tempdir().expect("tmpdir");
    let config_dir = tmp.path().join("config");
    let state_dir = tmp.path().join("state");

    run_init(&config_dir, &state_dir);

    for path in [
        &state_dir,
        &state_dir.join("generated-firma-ca"),
        &config_dir,
        &config_dir.join("policies"),
        &config_dir.join("issuance-policies"),
    ] {
        let mode = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o700,
            "expected {} to be mode 0700, got {mode:o}",
            path.display(),
        );
    }
}
