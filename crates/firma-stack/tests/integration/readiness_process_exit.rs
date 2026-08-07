use std::time::{Duration, Instant};

use firma_stack::{StackConfig, StackError};

#[test]
fn authority_exit_aborts_readiness_without_waiting_for_timeout() {
    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path().join("state");
    let config_path = dir.path().join("firma.toml");
    std::fs::write(&config_path, "[authority]\nlisten_addr = \"127.0.0.1:9\"\n")
        .expect("write config");
    let config = StackConfig {
        state_dir: Some(state_dir.clone()),
        config_file: config_path,
        // The stack launches the readiness child as `<exe> authority --config
        // <path>`. Pointed back at this test binary, libtest rejects the
        // unrecognized `--config` argument and exits 101 without opening the
        // readiness port, so startup observes the exit instead of waiting out
        // the readiness timeout.
        firma_bin: Some(std::env::current_exe().expect("test executable")),
    };

    let started_at = Instant::now();
    let Err(error) = firma_stack::spawn_stack(&config, &state_dir) else {
        panic!("an exited authority must fail startup");
    };

    let StackError::ReadinessProcessExited { component, status } = &error else {
        panic!("expected readiness process exit, got {error:?}");
    };
    assert_eq!(component, "authority");
    assert_eq!(status.code(), Some(101));
    assert!(
        started_at.elapsed() < Duration::from_secs(5),
        "startup waited for the readiness timeout after authority exit"
    );
    #[cfg(unix)]
    insta::assert_snapshot!(error.to_string(), @"'authority' exited before becoming ready: exit status: 101");
    #[cfg(windows)]
    insta::assert_snapshot!(error.to_string(), @"'authority' exited before becoming ready: exit code: 101");

    for name in ["authority.pid", "authority.listen", "stack.lock"] {
        assert!(!state_dir.join(name).exists(), "rollback left {name}");
    }
}

#[cfg(unix)]
#[test]
fn authority_exit_aborts_sidecar_readiness() {
    use std::os::unix::fs::PermissionsExt as _;

    // Keep Authority's socket ready while Sidecar's reserved socket is closed.
    // Authority exits after one second; Sidecar would exit after three. Startup
    // must therefore report Authority's exit while it is waiting on Sidecar,
    // rather than waiting for the later Sidecar exit or readiness timeout.
    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path().join("state");
    let config_path = dir.path().join("firma.toml");
    let fixture_path = dir.path().join("fixture.sh");
    let authority_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("authority listener");
    let authority_addr = authority_listener.local_addr().expect("authority address");
    let sidecar_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("reserve sidecar port");
    let sidecar_addr = sidecar_listener.local_addr().expect("sidecar address");
    drop(sidecar_listener);

    std::fs::write(
        &fixture_path,
        "#!/bin/sh\n\
         if [ \"$1\" = authority ]; then sleep 1; exit 23; fi\n\
         if [ \"$1\" = sidecar ]; then sleep 3; exit 24; fi\n",
    )
    .expect("write fixture");
    std::fs::set_permissions(&fixture_path, std::fs::Permissions::from_mode(0o700))
        .expect("make fixture executable");
    std::fs::write(
        &config_path,
        format!(
            "[authority]\nlisten_addr = \"{authority_addr}\"\n\
             [sidecar.interceptor]\nlisten_addr = \"{sidecar_addr}\"\n"
        ),
    )
    .expect("write config");
    let config = StackConfig {
        state_dir: Some(state_dir.clone()),
        config_file: config_path,
        firma_bin: Some(fixture_path),
    };

    let started_at = Instant::now();
    let Err(error) = firma_stack::spawn_stack(&config, &state_dir) else {
        panic!("authority exit must abort sidecar readiness");
    };
    drop(authority_listener);

    let StackError::ReadinessProcessExited { component, status } = error else {
        panic!("expected readiness process exit, got {error:?}");
    };
    assert_eq!(component, "authority");
    assert_eq!(status.code(), Some(23));
    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "startup waited for the sidecar fixture to exit"
    );
}
