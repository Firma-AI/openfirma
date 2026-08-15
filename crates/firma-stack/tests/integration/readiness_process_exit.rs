use std::time::{Duration, Instant};

#[cfg(unix)]
use camino::Utf8PathBuf;
use firma_stack::{StackConfig, StackError};
use firma_test_helpers::process_fixture;
#[cfg(unix)]
use firma_test_helpers::unix_fixture_script;

#[cfg(unix)]
const FIXTURE_MODE: &str = "FIRMA_TEST_READINESS_PROCESS_EXIT_MODE";
#[cfg(unix)]
const FIXTURE_STARTUP_REPORT: &str = "FIRMA_TEST_READINESS_PROCESS_EXIT_STARTUP_REPORT";
#[cfg(unix)]
const FIXTURE_SIDECAR_ARGS: &str = "FIRMA_TEST_READINESS_PROCESS_EXIT_SIDECAR_ARGS";
#[cfg(unix)]
#[derive(serde::Deserialize, serde::Serialize)]
struct LifecycleFixtureConfig {
    root: Utf8PathBuf,
    authority_addr: std::net::SocketAddr,
    sidecar_socket: Option<Utf8PathBuf>,
}

#[cfg(unix)]
fn utf8_path(path: &std::path::Path) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(path.to_path_buf()).expect("fixture path is UTF-8")
}

#[cfg(unix)]
fn write_lifecycle_fixture(path: &std::path::Path, config: LifecycleFixtureConfig, setup: &str) {
    crate::support::write_executable_script(
        path,
        unix_fixture_script(&lifecycle_fixture(config), setup),
    );
}

#[test]
fn authority_exit_aborts_readiness_without_waiting_for_timeout() {
    let dir = tempfile::tempdir().expect("dir");
    let state_dir = dir.path().join("state");
    let config_path = dir.path().join("firma.toml");
    // A valid [sidecar] section lets the eager plan build succeed; the authority
    // child still exits before readiness, which is what this test exercises.
    std::fs::write(
        &config_path,
        "[authority]\nlisten_addr = \"127.0.0.1:9\"\n\
         [sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"127.0.0.1:9\"\n",
    )
    .expect("write config");
    let config = StackConfig {
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

    let StackError::Orchestrator(
        firma_process_orchestrator::OrchestratorError::ReadinessProcessExited { component, status },
    ) = &error
    else {
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
    use crate::support::write_executable_script;

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

    write_executable_script(
        &fixture_path,
        "#!/bin/sh\n\
         if [ \"$1\" = authority ]; then sleep 1; exit 23; fi\n\
         if [ \"$1\" = sidecar ]; then sleep 3; exit 24; fi\n",
    );
    std::fs::write(
        &config_path,
        format!(
            "[authority]\nlisten_addr = \"{authority_addr}\"\n\
             [sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"{sidecar_addr}\"\n"
        ),
    )
    .expect("write config");
    let config = StackConfig {
        config_file: config_path,
        firma_bin: Some(fixture_path),
    };

    let started_at = Instant::now();
    let Err(error) = firma_stack::spawn_stack(&config, &state_dir) else {
        panic!("authority exit must abort sidecar readiness");
    };
    drop(authority_listener);

    let StackError::Orchestrator(
        firma_process_orchestrator::OrchestratorError::ReadinessProcessExited { component, status },
    ) = error
    else {
        panic!("expected readiness process exit, got {error:?}");
    };
    assert_eq!(component, "authority");
    assert_eq!(status.code(), Some(23));
    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "startup waited for the sidecar fixture to exit"
    );
}

#[cfg(unix)]
fn wait_for_file_while_starting<'scope>(
    path: &std::path::Path,
    startup: std::thread::ScopedJoinHandle<'scope, Result<firma_stack::RunningStack, StackError>>,
) -> std::thread::ScopedJoinHandle<'scope, Result<firma_stack::RunningStack, StackError>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if path.exists() {
            return startup;
        }
        if startup.is_finished() {
            let result = match startup.join() {
                Ok(result) => result,
                Err(payload) => {
                    eprintln!(
                        "stack startup thread panicked before {} appeared",
                        path.display()
                    );
                    std::panic::resume_unwind(payload);
                }
            };
            match result {
                Ok(mut stack) => {
                    let shutdown = stack.shutdown(Duration::ZERO);
                    panic!(
                        "stack startup completed before {} appeared; shutdown result: {shutdown:?}",
                        path.display()
                    );
                }
                Err(error) => panic!(
                    "stack startup failed before {} appeared: {error:?}",
                    path.display()
                ),
            }
        }
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn sidecar_exit_before_publication_rolls_back_ready_authority() {
    let outcome = run_sidecar_exit_and_assert_rollback(StackScenario::DynamicAuthority);
    assert!(
        outcome.sidecar_args.contains(&format!(
            "--authority-connect-addr\n{}\n",
            outcome.authority_addr
        )),
        "Sidecar command did not use current Authority publication: {}",
        outcome.sidecar_args
    );
}

#[cfg(unix)]
#[test]
fn fixed_authority_does_not_override_sidecar_connect_address() {
    let outcome = run_sidecar_exit_and_assert_rollback(StackScenario::FixedAuthority);
    assert!(!outcome.sidecar_args.contains("--authority-connect-addr"));
}

#[cfg(unix)]
#[test]
fn dynamic_authority_does_not_enable_disabled_sidecar_authority_client() {
    let outcome = run_sidecar_exit_and_assert_rollback(StackScenario::DisabledAuthorityClient);
    assert!(!outcome.sidecar_args.contains("--authority-connect-addr"));
}

#[cfg(unix)]
#[test]
fn unix_sidecar_publication_matches_planned_endpoint() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    let state_dir = root.join("state");
    let config_path = root.join("firma.toml");
    let fixture_path = root.join("fixture.sh");
    let sidecar_socket = root.join("sidecar.sock");
    let authority_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("authority listener");
    let authority_addr = authority_listener.local_addr().expect("authority address");

    write_lifecycle_fixture(
        &fixture_path,
        LifecycleFixtureConfig {
            root: utf8_path(root),
            authority_addr,
            sidecar_socket: Some(utf8_path(&sidecar_socket)),
        },
        &format!(
            "export {FIXTURE_STARTUP_REPORT}=\"$5\"\n\
             if [ \"$1\" = authority ]; then\n\
               export {FIXTURE_MODE}=authority\n\
             else\n\
               export {FIXTURE_MODE}=sidecar-unix\n\
             fi"
        ),
    );
    std::fs::write(
        &config_path,
        format!(
            "[authority]\nlisten_addr = \"{authority_addr}\"\n\
             [sidecar.interceptor]\nmode = \"unix_socket\"\nsocket_path = \"{}\"\n",
            sidecar_socket.display()
        ),
    )
    .expect("write config");
    let config = StackConfig {
        config_file: config_path,
        firma_bin: Some(fixture_path),
    };

    let mut stack = firma_stack::spawn_stack(&config, &state_dir)
        .expect("Unix Sidecar publication should satisfy readiness");
    let endpoint = std::fs::read_to_string(state_dir.join("sidecar.listen"))
        .expect("read canonical Sidecar endpoint");
    assert_eq!(endpoint, format!("unix:{}\n", sidecar_socket.display()));
    stack
        .shutdown(Duration::ZERO)
        .expect("shut down fixture stack");
}

process_fixture! {
    #[cfg(unix)]
    fn lifecycle_fixture(config: LifecycleFixtureConfig) {
        let mode = std::env::var(FIXTURE_MODE).expect("fixture mode");
        if mode == "authority" {
            let startup_report = std::path::PathBuf::from(
                std::env::var_os(FIXTURE_STARTUP_REPORT).expect("fixture startup report"),
            );
            firma_stack::publish_startup_report(
                &startup_report,
                &firma_stack::ComponentEndpoint::Tcp(config.authority_addr),
            )
            .expect("publish fixture startup report");
            loop {
                std::thread::sleep(Duration::from_mins(1));
            }
        }

        if mode == "sidecar-unix" {
            let socket = config
                .sidecar_socket
                .expect("fixture Sidecar socket")
                .into_std_path_buf();
            let listener = std::os::unix::net::UnixListener::bind(&socket)
                .expect("bind fixture Sidecar socket");
            let startup_report = std::path::PathBuf::from(
                std::env::var_os(FIXTURE_STARTUP_REPORT).expect("fixture startup report"),
            );
            firma_stack::publish_startup_report(
                &startup_report,
                &firma_stack::ComponentEndpoint::Unix(
                    firma_stack::UnixEndpoint::new(socket).expect("valid Unix socket path"),
                ),
            )
            .expect("publish fixture startup report");
            let _listener = listener;
            loop {
                std::thread::sleep(Duration::from_mins(1));
            }
        }

        assert_eq!(mode, "sidecar");
        let mut sidecar_args = std::env::var(FIXTURE_SIDECAR_ARGS).expect("fixture Sidecar args");
        sidecar_args.push('\n');
        std::fs::write(config.root.join("sidecar.args"), sidecar_args)
            .expect("capture Sidecar arguments");
        std::fs::write(config.root.join("sidecar.args.ready"), [])
            .expect("publish Sidecar arguments");
        while !config.root.join("release-sidecar").exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(25);
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum StackScenario {
    DynamicAuthority,
    FixedAuthority,
    DisabledAuthorityClient,
}

#[cfg(unix)]
struct StartupOutcome {
    authority_addr: std::net::SocketAddr,
    sidecar_args: String,
}

#[cfg(unix)]
#[expect(
    clippy::too_many_lines,
    reason = "one stack lifecycle scenario keeps launch and rollback assertions together"
)]
fn run_sidecar_exit_and_assert_rollback(scenario: StackScenario) -> StartupOutcome {
    use nix::errno::Errno;
    use nix::unistd::Pid;

    use crate::support::{ProcessGroupCleanup, wait_for_pidfile};

    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    let state_dir = root.join("state");
    let config_path = root.join("firma.toml");
    let fixture_path = root.join("fixture.sh");
    let release_sidecar = root.join("release-sidecar");
    let authority_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("authority listener");
    let authority_addr = authority_listener.local_addr().expect("authority address");
    let requested_authority_addr = match scenario {
        StackScenario::DynamicAuthority | StackScenario::DisabledAuthorityClient => {
            "127.0.0.1:0".parse().expect("dynamic Authority address")
        }
        StackScenario::FixedAuthority => authority_addr,
    };

    write_lifecycle_fixture(
        &fixture_path,
        LifecycleFixtureConfig {
            root: utf8_path(root),
            authority_addr,
            sidecar_socket: None,
        },
        &format!(
            "if [ \"$1\" = authority ]; then\n\
               export {FIXTURE_MODE}=authority\n\
               export {FIXTURE_STARTUP_REPORT}=\"$5\"\n\
             fi\n\
             if [ \"$1\" = sidecar ]; then\n\
               export {FIXTURE_MODE}=sidecar\n\
               export {FIXTURE_SIDECAR_ARGS}=\"$(printf '%s\\n' \"$@\")\"\n\
             fi"
        ),
    );
    let sidecar_authority = match scenario {
        StackScenario::DynamicAuthority | StackScenario::FixedAuthority => {
            "[sidecar.authority]\nurl = \"http://localhost:50051\"\n"
        }
        StackScenario::DisabledAuthorityClient => "",
    };
    std::fs::write(
        &config_path,
        format!(
            "[authority]\nlisten_addr = \"{requested_authority_addr}\"\n\
             [sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"127.0.0.1:9\"\n\
             {sidecar_authority}"
        ),
    )
    .expect("write config");
    let config = StackConfig {
        config_file: config_path,
        firma_bin: Some(fixture_path),
    };

    let (result, authority_pid, mut cleanup, sidecar_args) = std::thread::scope(|scope| {
        let startup = scope.spawn(|| firma_stack::spawn_stack(&config, &state_dir));
        let startup = wait_for_file_while_starting(&state_dir.join("authority.listen"), startup);
        let authority_pid = wait_for_pidfile(&state_dir.join("authority.pid"));
        let cleanup = ProcessGroupCleanup::new(authority_pid);
        wait_for_pidfile(&state_dir.join("sidecar.pid"));
        let sidecar_args_path = root.join("sidecar.args");
        let startup = wait_for_file_while_starting(&root.join("sidecar.args.ready"), startup);
        let sidecar_args =
            std::fs::read_to_string(sidecar_args_path).expect("captured Sidecar arguments");
        assert!(
            !state_dir.join("sidecar.listen").exists(),
            "Sidecar canonical listen state appeared before publication"
        );
        std::fs::write(&release_sidecar, []).expect("release sidecar fixture");
        let result = startup.join().expect("startup thread");
        (result, authority_pid, cleanup, sidecar_args)
    });

    let error = result.err().expect("Sidecar exit must fail startup");
    let StackError::Orchestrator(
        firma_process_orchestrator::OrchestratorError::ReadinessProcessExited { component, status },
    ) = error
    else {
        panic!("expected readiness process exit, got {error:?}");
    };
    assert_eq!(component, "sidecar");
    assert_eq!(status.code(), Some(25));
    let authority_pid = Pid::from_raw(i32::try_from(authority_pid).expect("PID fits i32"));
    assert_eq!(
        nix::sys::signal::kill(authority_pid, None),
        Err(Errno::ESRCH),
        "startup rollback left Authority running"
    );
    cleanup.disarm();

    for name in [
        "authority.pid",
        "authority.listen",
        "sidecar.pid",
        "sidecar.listen",
        "stack.lock",
    ] {
        assert!(!state_dir.join(name).exists(), "rollback left {name}");
    }

    StartupOutcome {
        authority_addr,
        sidecar_args,
    }
}
