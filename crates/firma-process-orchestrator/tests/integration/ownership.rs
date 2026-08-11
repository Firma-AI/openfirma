//! Ownership, generation fencing, and publication through production APIs.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier, mpsc};
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentPlanContext, ComponentSpec, LifecycleTimeouts, OrchestratorError, RunningStack,
    ShutdownError, StackGeneration, StackTopology, StartError, publish_startup_report,
    spawn_stack_from_plan, start_detached, start_foreground_from_plan, stop_components,
    supervise_owned_generation_from_plan,
};
use firma_runtime_state::UserProcessId;
use fs2::FileExt as _;

const CHILD_MARKER: &str = "FIRMA_ORCHESTRATOR_CHILD_MARKER";
const CHILD_LISTEN: &str = "FIRMA_ORCHESTRATOR_CHILD_LISTEN";
const CHILD_PUBLICATION: &str = "FIRMA_ORCHESTRATOR_CHILD_PUBLICATION";
const CHILD_RELEASE: &str = "FIRMA_ORCHESTRATOR_CHILD_RELEASE";
const CHILD_BLOCK_PIDFILE: &str = "FIRMA_ORCHESTRATOR_CHILD_BLOCK_PIDFILE";
const SUPERVISOR_STATE_DIR: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_STATE_DIR";
const SUPERVISOR_GENERATION: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_GENERATION";
const SUPERVISOR_MODE: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_MODE";
const SUPERVISOR_SENTINEL_PID: &str = "FIRMA_ORCHESTRATOR_SUPERVISOR_SENTINEL_PID";

fn fast_timeouts() -> LifecycleTimeouts {
    LifecycleTimeouts {
        graceful_teardown: Duration::ZERO,
        ..LifecycleTimeouts::default()
    }
}

struct ProcessCleanup(Vec<u32>);

impl ProcessCleanup {
    fn new(pids: impl IntoIterator<Item = u32>) -> Self {
        Self(pids.into_iter().collect())
    }

    fn disarm(mut self) {
        self.0.clear();
    }
}

impl Drop for ProcessCleanup {
    fn drop(&mut self) {
        for pid in &self.0 {
            best_effort_terminate_scope(*pid);
        }
    }
}

#[test]
fn owned_shutdown_is_idempotent_and_ignores_pidfiles() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);
    std::fs::remove_file(dir.path().join("authority.pid")).expect("remove pidfile");
    std::fs::write(dir.path().join("sidecar.pid"), "not-a-pid\n").expect("corrupt pidfile");

    stack.shutdown(Duration::ZERO).expect("owned shutdown");
    let repeated = stack.shutdown(Duration::ZERO).expect("repeated shutdown");

    assert!(!repeated.forced);
    assert_all_absent(&pids);
    assert!(!dir.path().join("stack.lock").exists());
}

#[test]
fn cleanup_attempts_all_artifacts_before_retaining_generation_lock() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority"]);
    let pidfile = dir.path().join("authority.pid");
    std::fs::remove_file(&pidfile).expect("remove component pidfile");
    std::fs::create_dir(&pidfile).expect("block component pidfile cleanup");

    let error = stack
        .shutdown(Duration::ZERO)
        .expect_err("blocked state cleanup must fail");

    let ShutdownError::StateCleanup(error) = error else {
        panic!("process teardown must be reported as complete");
    };
    assert!(matches!(error, OrchestratorError::RuntimeState(_)));
    assert_all_absent(&pids);
    assert!(!dir.path().join("authority.listen").exists());
    assert!(!dir.path().join("stack.pid").exists());
    assert!(dir.path().join("stack.lock").exists());

    std::fs::remove_dir(pidfile).expect("remove pidfile blocker");
    stop_components(dir.path(), Duration::ZERO, &topology(&["authority"]))
        .expect("retry retained generation cleanup");
    assert!(!dir.path().join("stack.lock").exists());
}

#[test]
fn owned_shutdown_terminates_children_when_state_transaction_is_busy() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);
    let cleanup = ProcessCleanup::new(pids.iter().copied());
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join(".stack-state.lock"))
        .expect("open transaction lock");
    lock.lock_exclusive().expect("hold transaction lock");

    let started = Instant::now();
    let error = stack
        .shutdown(Duration::ZERO)
        .expect_err("contended cleanup must fail");
    let ShutdownError::StateCleanup(error) = error else {
        panic!("process teardown must be reported as complete");
    };
    assert!(matches!(error, OrchestratorError::RuntimeStateBusy { .. }));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_all_absent(&pids);
    fs2::FileExt::unlock(&lock).expect("release transaction lock");
    stop_components(
        dir.path(),
        Duration::ZERO,
        &topology(&["authority", "sidecar"]),
    )
    .expect("retry cleanup");
    cleanup.disarm();
}

#[test]
fn authority_exit_tears_down_owned_foreground_stack() {
    assert_component_exit_tears_down_foreground_stack(0);
}

#[test]
fn sidecar_exit_tears_down_owned_foreground_stack() {
    assert_component_exit_tears_down_foreground_stack(1);
}

#[test]
fn authority_exit_during_startup_reports_readiness_process_exited() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let startup = std::thread::spawn(move || {
        spawn_stack_from_plan(
            &topology(&["authority", "sidecar"]),
            delayed_component_planner(&state_dir, &["authority", "sidecar"]),
            &state_dir,
            fast_timeouts(),
        )
    });
    std::fs::write(dir.path().join("authority.release"), []).expect("release authority");
    let authority_pid = wait_for_marker(&dir.path().join("authority.marker"));
    terminate_process(authority_pid);

    let Err(error) = startup.join().expect("join startup") else {
        panic!("authority exit must fail startup");
    };
    assert!(matches!(
        error,
        StartError::Orchestrator(OrchestratorError::ReadinessProcessExited { .. })
    ));
}

#[test]
fn wildcard_child_publication_uses_loopback_canonical_endpoint() {
    let dir = tempfile::tempdir().expect("state dir");
    let mut stack = spawn_stack_from_plan(
        &topology(&["worker"]),
        |context| {
            let publication =
                context.child_published(firma_process_orchestrator::ComponentEndpoint::Tcp(
                    "0.0.0.0:0".parse().expect("wildcard child bind endpoint"),
                ));
            let mut command = fixture_command();
            command
                .env(CHILD_LISTEN, "0.0.0.0:0")
                .env(CHILD_PUBLICATION, publication.startup_report_path());
            Ok::<_, std::convert::Infallible>(ComponentSpec {
                command,
                readiness: publication.into_readiness(),
            })
        },
        dir.path(),
        fast_timeouts(),
    )
    .expect("wildcard child readiness");

    let canonical: std::net::SocketAddr = std::fs::read_to_string(dir.path().join("worker.listen"))
        .expect("read canonical worker endpoint")
        .trim()
        .parse()
        .expect("parse canonical worker endpoint");
    assert_eq!(canonical.ip(), std::net::Ipv4Addr::LOCALHOST);
    std::net::TcpStream::connect(canonical).expect("dial canonical worker endpoint");
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn external_stop_terminates_targets_but_retains_malformed_generation_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);
    std::fs::write(dir.path().join("stack.lock"), "not-a-generation\n")
        .expect("corrupt generation");

    let stop_dir = dir.path().to_path_buf();
    let stopper = std::thread::spawn(move || {
        stop_components(
            &stop_dir,
            Duration::from_secs(1),
            &topology(&["authority", "sidecar"]),
        )
    });
    std::thread::sleep(Duration::from_millis(100));
    let _owner_error = stack
        .shutdown(Duration::ZERO)
        .expect_err("owner must retain malformed state");
    let error = stopper
        .join()
        .expect("join external stop")
        .expect_err("malformed generation must prevent cleanup");

    assert!(
        matches!(error, OrchestratorError::InvalidStackGeneration { .. }),
        "unexpected stop error: {error:?}"
    );
    assert_all_absent(&pids);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("stack.lock")).expect("retained lock"),
        "not-a-generation\n"
    );
    for name in ["authority", "sidecar"] {
        assert!(dir.path().join(format!("{name}.pid")).exists());
        assert!(dir.path().join(format!("{name}.listen")).exists());
    }
}

#[test]
fn old_owner_does_not_remove_replacement_generation_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);
    let replacement = StackGeneration::default();
    std::fs::write(dir.path().join("stack.lock"), format!("{replacement}\n"))
        .expect("publish replacement generation fixture");
    std::fs::write(dir.path().join("replacement.marker"), "new owner\n")
        .expect("write replacement state");

    stack.shutdown(Duration::ZERO).expect("old owner shutdown");

    assert_all_absent(&pids);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("stack.lock")).expect("replacement lock"),
        format!("{replacement}\n")
    );
    assert!(dir.path().join("replacement.marker").exists());
}

#[test]
fn already_running_precedes_staged_plan_failure() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, _pids) = spawn_stack(dir.path(), &["authority"]);
    let mut planner_called = false;

    let result = spawn_stack_from_plan(
        &topology(&["authority"]),
        |_| {
            planner_called = true;
            Err::<ComponentSpec, _>("planner must not run")
        },
        dir.path(),
        fast_timeouts(),
    );

    assert!(matches!(
        result,
        Err(StartError::Orchestrator(
            OrchestratorError::AlreadyRunning { .. }
        ))
    ));
    assert!(!planner_called);
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
}

#[test]
fn startup_guard_rollback_preserves_replacement_generation_runtime_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut child, addr) = spawn_published_fixture(dir.path(), "replacement-sentinel");
    let sentinel_pid = child.id();
    let cleanup = ProcessCleanup::new([sentinel_pid]);
    let replacement = StackGeneration::default();
    let result = spawn_stack_from_plan(
        &topology(&["authority"]),
        |_| {
            std::fs::write(dir.path().join("stack.lock"), format!("{replacement}\n"))
                .expect("replace generation");
            let pid = UserProcessId::new(sentinel_pid).expect("sentinel PID");
            firma_runtime_state::pidfile::write(&dir.path().join("stack.pid"), pid)
                .expect("write replacement supervisor");
            firma_runtime_state::pidfile::write(&dir.path().join("authority.pid"), pid)
                .expect("write replacement component");
            std::fs::write(dir.path().join("authority.listen"), format!("{addr}\n"))
                .expect("write replacement listen state");
            firma_runtime_state::pidfile::write(
                &dir.path().join(format!("stack.{sentinel_pid}.ready")),
                pid,
            )
            .expect("write replacement ready state");
            Err::<ComponentSpec, &'static str>("planned failure")
        },
        dir.path(),
        fast_timeouts(),
    );
    let Err(error) = result else {
        panic!("plan unexpectedly succeeded");
    };

    let StartError::Rollback {
        operation,
        rollback,
    } = error
    else {
        panic!("generation replacement did not report guarded cleanup refusal");
    };
    assert!(matches!(*operation, StartError::Plan("planned failure")));
    assert!(matches!(*rollback, OrchestratorError::Platform(_)));
    assert_process_present(sentinel_pid);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("stack.lock")).expect("replacement lock"),
        format!("{replacement}\n")
    );
    for file in [
        "stack.pid".to_string(),
        "authority.pid".to_string(),
        "authority.listen".to_string(),
        format!("stack.{sentinel_pid}.ready"),
    ] {
        assert!(dir.path().join(file).exists());
    }
    terminate_process(sentinel_pid);
    child.wait().expect("collect sentinel");
    assert_process_absent(sentinel_pid);
    cleanup.disarm();
}

#[test]
fn stop_waits_for_start_plan_transaction() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let topology = topology(&["authority"]);
    let barrier = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let (start_tx, start_rx) = mpsc::channel();
    let start_dir = state_dir.clone();
    let start_topology = topology.clone();
    let plan_barrier = Arc::clone(&barrier);
    let plan_release = Arc::clone(&release);
    let starter = std::thread::spawn(move || {
        let mut planner = component_planner(&start_dir, &["authority"]);
        let result = spawn_stack_from_plan(
            &start_topology,
            |context| {
                plan_barrier.wait();
                plan_release.wait();
                planner(context)
            },
            &start_dir,
            fast_timeouts(),
        );
        let _ = start_tx.send(result);
    });
    barrier.wait();

    let stop_dir = state_dir;
    let stop_topology = topology;
    let (stop_tx, stop_rx) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        let _ = stop_tx.send(stop_components(&stop_dir, Duration::ZERO, &stop_topology));
    });
    assert!(matches!(
        stop_rx.recv_timeout(Duration::from_millis(200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));

    release.wait();
    let stack = start_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("startup result")
        .expect("startup");
    drop(stack);
    stop_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("stop result")
        .expect("serialized stop");
    starter.join().expect("join starter");
    stopper.join().expect("join stopper");
}

#[test]
fn stop_waits_for_partial_component_publication() {
    for published_components in [1, 2] {
        assert_stop_waits_for_partial_publication(published_components);
    }
}

#[test]
fn generation_publication_is_atomic_for_concurrent_readers() {
    for _ in 0..30 {
        let dir = tempfile::tempdir().expect("state dir");
        let state_dir = dir.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(2));
        let writer_barrier = Arc::clone(&barrier);
        let writer_release = Arc::clone(&release);
        let writer_dir = state_dir.clone();
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            spawn_stack_from_plan(
                &topology(&["authority"]),
                |_| {
                    writer_release.wait();
                    Err::<ComponentSpec, _>("stop after observing publication")
                },
                &writer_dir,
                fast_timeouts(),
            )
        });
        let reader_barrier = Arc::clone(&barrier);
        let reader_dir = state_dir.clone();
        let (published_tx, published_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            reader_barrier.wait();
            loop {
                if let Ok(value) = std::fs::read_to_string(reader_dir.join("stack.lock")) {
                    value
                        .trim()
                        .parse::<StackGeneration>()
                        .expect("atomic generation");
                    let _ = published_tx.send(());
                    break;
                }
                std::thread::yield_now();
            }
            for _ in 0..100 {
                if let Ok(value) = std::fs::read_to_string(reader_dir.join("stack.lock")) {
                    value
                        .trim()
                        .parse::<StackGeneration>()
                        .expect("atomic generation");
                }
                std::thread::yield_now();
            }
        });
        barrier.wait();
        published_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("publication observed");
        release.wait();
        assert!(matches!(
            writer.join().expect("join writer"),
            Err(StartError::Plan("stop after observing publication"))
        ));
        reader.join().expect("join reader");
        assert!(!state_dir.join("stack.lock").exists());
    }
}

#[test]
fn explicit_detach_transfers_real_children_to_reaper() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);
    stack.detach().expect("detach stack");

    stop_components(
        dir.path(),
        Duration::ZERO,
        &topology(&["authority", "sidecar"]),
    )
    .expect("external stop");
    assert_all_absent(&pids);
}

#[test]
fn persistent_collector_does_not_starve_later_children() {
    let long_lived_dir = tempfile::tempdir().expect("long-lived state dir");
    let short_lived_dir = tempfile::tempdir().expect("short-lived state dir");
    let (mut long_lived, long_lived_pids) = spawn_stack(long_lived_dir.path(), &["authority"]);
    long_lived.detach().expect("detach long-lived stack");

    let (short_lived, short_lived_pids) = spawn_stack(short_lived_dir.path(), &["authority"]);
    drop(short_lived);

    assert_all_absent(&short_lived_pids);
    stop_components(
        short_lived_dir.path(),
        Duration::ZERO,
        &topology(&["authority"]),
    )
    .expect("clean short-lived stack state");
    stop_components(
        long_lived_dir.path(),
        Duration::ZERO,
        &topology(&["authority"]),
    )
    .expect("stop long-lived stack");
    assert_all_absent(&long_lived_pids);
}

#[test]
fn dropping_owner_hard_terminates_children_and_retains_state() {
    let dir = tempfile::tempdir().expect("state dir");
    let (stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);

    drop(stack);

    assert_all_absent(&pids);
    assert!(dir.path().join("stack.lock").exists());
    stop_components(
        dir.path(),
        Duration::ZERO,
        &topology(&["authority", "sidecar"]),
    )
    .expect("clean dropped stack state");
}

#[cfg(unix)]
#[test]
fn dropped_owner_hard_terminates_descendant_process_group() {
    let dir = tempfile::tempdir().expect("state dir");
    let marker = dir.path().join("descendant.pid");
    let (addr, listener) = reserve_address();
    let mut command = Command::new("sh");
    command.args(["-c", "sleep 600 & echo $! > \"$DESCENDANT\"; wait"]);
    command.env("DESCENDANT", &marker);
    let mut command = Some(command);
    let stack = spawn_stack_from_plan(
        &topology(&["authority"]),
        |_| {
            Ok::<_, std::convert::Infallible>(ComponentSpec {
                command: command.take().expect("single component planned once"),
                readiness: firma_process_orchestrator::Readiness::Configured(
                    firma_process_orchestrator::ComponentEndpoint::Tcp(addr),
                ),
            })
        },
        dir.path(),
        fast_timeouts(),
    )
    .expect("spawn grouped leader");
    let descendant = wait_for_marker(&marker);
    drop(listener);
    drop(stack);

    assert_process_absent(descendant);
    stop_components(dir.path(), Duration::ZERO, &topology(&["authority"]))
        .expect("clean process group state");
}

#[test]
fn detached_launcher_exit_before_readiness_rolls_back_generation() {
    let dir = tempfile::tempdir().expect("state dir");
    let Err(error) = start_detached(
        &topology(&["authority"]),
        dir.path(),
        fast_timeouts(),
        |_| exiting_command(),
    ) else {
        panic!("exiting supervisor unexpectedly attached");
    };

    assert!(matches!(error, OrchestratorError::Platform(_)));
    assert!(!dir.path().join("stack.lock").exists());
    assert!(!dir.path().join("stack.pid").exists());
}

#[test]
fn detached_component_exit_tears_down_peer_and_supervisor_state() {
    let dir = tempfile::tempdir().expect("state dir");
    start_detached(
        &topology(&["authority", "sidecar"]),
        dir.path(),
        fast_timeouts(),
        |generation| supervisor_command(dir.path(), generation, "run"),
    )
    .expect("attach detached supervisor");
    let pids = [
        wait_for_marker(&dir.path().join("authority.marker")),
        wait_for_marker(&dir.path().join("sidecar.marker")),
    ];
    let supervisor_pid = read_pidfile(&dir.path().join("stack.pid"));
    let cleanup = ProcessCleanup::new(pids.into_iter().chain([supervisor_pid]));

    terminate_process(pids[0]);
    assert_all_absent(&pids);
    assert_process_absent(supervisor_pid);
    for path in ["stack.lock", "stack.pid", "authority.pid", "sidecar.pid"] {
        assert!(!dir.path().join(path).exists(), "{path} retained");
    }
    cleanup.disarm();
}

#[test]
fn stale_detached_launcher_rollback_does_not_signal_replacement_target() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut sentinel, _) = spawn_published_fixture(dir.path(), "detached-sentinel");
    let sentinel_pid = sentinel.id();
    let cleanup = ProcessCleanup::new([sentinel_pid]);

    let result = start_detached(
        &topology(&["authority"]),
        dir.path(),
        fast_timeouts(),
        |generation| {
            let mut command = supervisor_command(dir.path(), generation, "replace");
            command.env(SUPERVISOR_SENTINEL_PID, sentinel_pid.to_string());
            command
        },
    );

    assert!(result.is_err(), "replacement fixture unexpectedly attached");
    assert_process_present(sentinel_pid);
    assert!(dir.path().join("stack.lock").exists());
    assert!(dir.path().join("authority.pid").exists());
    terminate_process(sentinel_pid);
    sentinel.wait().expect("collect sentinel");
    assert_process_absent(sentinel_pid);
    cleanup.disarm();
}

#[test]
fn component_pidfile_publication_failure_collects_spawned_child() {
    let dir = tempfile::tempdir().expect("state dir");
    let mut planner = component_planner(dir.path(), &["authority", "sidecar"]);
    let mut index = 0;
    let Err(error) = spawn_stack_from_plan(
        &topology(&["authority", "sidecar"]),
        |context| {
            let mut spec = planner(context)?;
            if index == 0 {
                spec.command
                    .env(CHILD_BLOCK_PIDFILE, dir.path().join("sidecar.pid"));
            }
            index += 1;
            Ok::<_, std::convert::Infallible>(spec)
        },
        dir.path(),
        fast_timeouts(),
    ) else {
        panic!("pidfile publication unexpectedly succeeded");
    };

    let StartError::Rollback {
        operation,
        rollback: _,
    } = error
    else {
        panic!("pidfile failure did not report explicit rollback failure");
    };
    assert!(matches!(*operation, StartError::Orchestrator(_)));
    let authority_pid = wait_for_marker(&dir.path().join("authority.marker"));
    assert_process_absent(authority_pid);
    std::fs::remove_dir(dir.path().join("sidecar.pid")).expect("remove pidfile blocker");
    stop_components(
        dir.path(),
        Duration::ZERO,
        &topology(&["authority", "sidecar"]),
    )
    .expect("clean retained state");
    assert!(!dir.path().join("stack.lock").exists());
    assert!(!dir.path().join("authority.pid").exists());
    assert!(!dir.path().join("authority.listen").exists());
    assert!(!dir.path().join("sidecar.listen").exists());
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn owned_child_fixture() {
    if let (Some(state_dir), Some(generation)) = (
        std::env::var_os(SUPERVISOR_STATE_DIR),
        std::env::var_os(SUPERVISOR_GENERATION),
    ) {
        let state_dir = Path::new(&state_dir);
        let generation = generation
            .to_string_lossy()
            .parse::<StackGeneration>()
            .expect("parse supervisor generation");
        if std::env::var(SUPERVISOR_MODE).as_deref() == Ok("replace") {
            let replacement = StackGeneration::default();
            let sentinel = std::env::var(SUPERVISOR_SENTINEL_PID)
                .expect("sentinel PID")
                .parse::<u32>()
                .expect("parse sentinel PID");
            let sentinel = UserProcessId::new(sentinel).expect("sentinel PID");
            std::fs::write(state_dir.join("stack.lock"), format!("{replacement}\n"))
                .expect("publish replacement generation");
            firma_runtime_state::pidfile::write(&state_dir.join("stack.pid"), sentinel)
                .expect("write replacement owner");
            firma_runtime_state::pidfile::write(&state_dir.join("authority.pid"), sentinel)
                .expect("write replacement component");
            return;
        }
        supervise_owned_generation_from_plan(
            &topology(&["authority", "sidecar"]),
            component_planner(state_dir, &["authority", "sidecar"]),
            state_dir,
            generation,
            fast_timeouts(),
        )
        .expect("supervise detached fixture");
        return;
    }
    if let Some(address) = std::env::var_os(CHILD_LISTEN) {
        if let Some(release) = std::env::var_os(CHILD_RELEASE) {
            while !Path::new(&release).exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(path) = std::env::var_os(CHILD_BLOCK_PIDFILE) {
            std::fs::create_dir(path).expect("create blocking pidfile directory");
        }
        let listener = std::net::TcpListener::bind(address.to_string_lossy().as_ref())
            .expect("bind component readiness listener");
        if let Some(publication) = std::env::var_os(CHILD_PUBLICATION) {
            publish_startup_report(
                Path::new(&publication),
                &firma_process_orchestrator::ComponentEndpoint::Tcp(
                    listener.local_addr().expect("effective component endpoint"),
                ),
            )
            .expect("publish component endpoint");
        }
        if let Some(marker) = std::env::var_os(CHILD_MARKER) {
            std::fs::write(marker, std::process::id().to_string()).expect("write marker");
        }
        println!("{}", std::process::id());
        std::io::stdout().flush().expect("flush PID");
        loop {
            let _ = listener.accept();
        }
    }
}

fn assert_component_exit_tears_down_foreground_stack(exiting_component: usize) {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let (result_tx, result_rx) = mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let result = start_foreground_from_plan(
            &topology(&["authority", "sidecar"]),
            component_planner(&state_dir, &["authority", "sidecar"]),
            &state_dir,
            fast_timeouts(),
        );
        let _ = result_tx.send(result);
    });
    let pids = [
        wait_for_marker(&dir.path().join("authority.marker")),
        wait_for_marker(&dir.path().join("sidecar.marker")),
    ];
    wait_for_file(&dir.path().join("authority.listen"));
    wait_for_file(&dir.path().join("sidecar.listen"));
    wait_for_transaction_release(dir.path());
    terminate_process(pids[exiting_component]);

    result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("foreground result")
        .expect("foreground teardown");
    supervisor.join().expect("join supervisor");
    assert_all_absent(&pids);
    assert!(!dir.path().join("stack.lock").exists());
}

fn spawn_stack(state_dir: &Path, names: &[&str]) -> (RunningStack, Vec<u32>) {
    let stack = spawn_stack_from_plan(
        &topology(names),
        component_planner(state_dir, names),
        state_dir,
        fast_timeouts(),
    )
    .expect("spawn public stack");
    let pids = names
        .iter()
        .map(|name| wait_for_marker(&state_dir.join(format!("{name}.marker"))))
        .collect();
    (stack, pids)
}

fn component_spec(context: &ComponentPlanContext<'_>, state_dir: &Path) -> ComponentSpec {
    let publication = context.child_published(firma_process_orchestrator::ComponentEndpoint::Tcp(
        "127.0.0.1:0".parse().expect("fixture bind endpoint"),
    ));
    let mut command = fixture_command();
    command
        .env_remove(SUPERVISOR_STATE_DIR)
        .env_remove(SUPERVISOR_GENERATION)
        .env_remove(SUPERVISOR_MODE)
        .env_remove(SUPERVISOR_SENTINEL_PID)
        .env(CHILD_LISTEN, "127.0.0.1:0")
        .env(CHILD_PUBLICATION, publication.startup_report_path())
        .env(
            CHILD_MARKER,
            state_dir.join(format!("{}.marker", context.name())),
        );
    ComponentSpec {
        command,
        readiness: publication.into_readiness(),
    }
}

fn component_planner<'a>(
    state_dir: &Path,
    names: &'a [&'a str],
) -> impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, std::convert::Infallible> + use<'a>
{
    let state_dir = state_dir.to_path_buf();
    let mut index = 0;
    move |context| {
        assert_eq!(context.name(), names[index]);
        assert!(
            names[..index]
                .iter()
                .all(|name| context.ready_endpoint(name).is_some()),
            "each staged invocation sees every prior ready endpoint"
        );
        assert!(context.ready_endpoint(names[index]).is_none());
        index += 1;
        Ok(component_spec(&context, &state_dir))
    }
}

fn delayed_component_planner<'a>(
    state_dir: &Path,
    names: &'a [&'a str],
) -> impl FnMut(ComponentPlanContext<'_>) -> Result<ComponentSpec, std::convert::Infallible> {
    let state_dir = state_dir.to_path_buf();
    let mut planner = component_planner(&state_dir, names);
    move |context| {
        let name = context.name().to_string();
        let mut spec = planner(context)?;
        spec.command
            .env(CHILD_RELEASE, state_dir.join(format!("{name}.release")));
        Ok(spec)
    }
}

fn assert_stop_waits_for_partial_publication(published_components: usize) {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let (start_tx, start_rx) = mpsc::channel();
    let start_dir = state_dir.clone();
    let starter = std::thread::spawn(move || {
        let result = spawn_stack_from_plan(
            &topology(&["authority", "sidecar"]),
            delayed_component_planner(&start_dir, &["authority", "sidecar"]),
            &start_dir,
            fast_timeouts(),
        );
        let _ = start_tx.send(result);
    });
    wait_for_file(&state_dir.join("authority.pid"));
    if published_components == 2 {
        std::fs::write(state_dir.join("authority.release"), []).expect("release authority");
        wait_for_file(&state_dir.join("sidecar.pid"));
    }
    let stop_dir = state_dir.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        let _ = stop_tx.send(stop_components(
            &stop_dir,
            Duration::ZERO,
            &topology(&["authority", "sidecar"]),
        ));
    });
    assert!(matches!(
        stop_rx.recv_timeout(Duration::from_millis(200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    std::fs::write(state_dir.join("authority.release"), []).expect("release authority");
    std::fs::write(state_dir.join("sidecar.release"), []).expect("release sidecar");
    let stack = start_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("startup result")
        .expect("startup");
    drop(stack);
    stop_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("stop result")
        .expect("serialized stop");
    starter.join().expect("join starter");
    stopper.join().expect("join stopper");
}

#[cfg(unix)]
fn reserve_address() -> (std::net::SocketAddr, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve address");
    (listener.local_addr().expect("reserved address"), listener)
}

fn spawn_published_fixture(
    state_dir: &Path,
    name: &str,
) -> (std::process::Child, std::net::SocketAddr) {
    let publication = state_dir.join(format!("{name}.endpoint"));
    let marker = state_dir.join(format!("{name}.marker"));
    let mut command = fixture_command();
    command
        .env(CHILD_LISTEN, "127.0.0.1:0")
        .env(CHILD_PUBLICATION, &publication)
        .env(CHILD_MARKER, &marker);
    let child = command.spawn().expect("spawn published fixture");
    wait_for_marker(&marker);
    let record = std::fs::read_to_string(publication).expect("read fixture endpoint");
    let addr = record
        .lines()
        .find_map(|line| line.strip_prefix("endpoint = \"")?.strip_suffix('"'))
        .expect("fixture endpoint field")
        .parse()
        .expect("parse fixture endpoint");
    (child, addr)
}

fn wait_for_transaction_release(state_dir: &Path) {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(state_dir.join(".stack-state.lock"))
        .expect("open transaction lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match lock.try_lock_shared() {
            Ok(()) => {
                fs2::FileExt::unlock(&lock).expect("release observed transaction lock");
                return;
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                assert!(
                    Instant::now() < deadline,
                    "startup transaction remained held"
                );
                std::thread::yield_now();
            }
            Err(std::fs::TryLockError::Error(error)) => {
                panic!("observe startup transaction: {error}")
            }
        }
    }
}

fn fixture_command() -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command.args(["--exact", "ownership::owned_child_fixture", "--ignored"]);
    command
}

fn supervisor_command(state_dir: &Path, generation: StackGeneration, mode: &str) -> Command {
    let mut command = fixture_command();
    command
        .env(SUPERVISOR_STATE_DIR, state_dir)
        .env(SUPERVISOR_GENERATION, generation.to_string())
        .env(SUPERVISOR_MODE, mode);
    command
}

fn exiting_command() -> Command {
    #[cfg(unix)]
    {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        command
    }
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.args(["/C", "exit 0"]);
        command
    }
}

fn topology(names: &[&str]) -> StackTopology {
    StackTopology::new(names.iter().copied()).expect("valid topology")
}

fn wait_for_marker(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(pid) = contents.trim().parse()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_all_absent(pids: &[u32]) {
    for pid in pids {
        assert_process_absent(*pid);
    }
}

fn assert_process_absent(pid: u32) {
    let process = UserProcessId::new(pid).expect("fixture PID");
    let deadline = Instant::now() + Duration::from_secs(5);
    while process.process_exists().expect("probe fixture") {
        assert!(Instant::now() < deadline, "process {pid} remains alive");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_process_present(pid: u32) {
    assert!(
        UserProcessId::new(pid)
            .expect("fixture PID")
            .process_exists()
            .expect("probe fixture"),
        "process {pid} is absent"
    );
}

fn read_pidfile(path: &Path) -> u32 {
    firma_runtime_state::pidfile::read(path)
        .expect("read pidfile")
        .expect("pidfile present")
        .get()
}

fn best_effort_terminate_scope(pid: u32) {
    #[cfg(unix)]
    {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX));
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-pid.as_raw()),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
}

fn terminate_process(pid: u32) {
    #[cfg(unix)]
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(pid).expect("PID fits i32")),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("terminate fixture");
    #[cfg(windows)]
    assert!(
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .expect("run taskkill")
            .success()
    );
}
