use super::*;

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
    assert_eq!(
        stack
            .handle()
            .component("worker")
            .expect("worker handle")
            .endpoint(),
        &firma_process_orchestrator::ComponentEndpoint::Tcp(canonical)
    );
    assert_eq!(canonical.ip(), std::net::Ipv4Addr::LOCALHOST);
    std::net::TcpStream::connect(canonical).expect("dial canonical worker endpoint");
    stack.shutdown(Duration::ZERO).expect("shutdown fixture");
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
fn component_pidfile_publication_failure_collects_spawned_child() {
    let dir = tempfile::tempdir().expect("state dir");
    let state_dir = dir.path().to_path_buf();
    let startup_dir = state_dir.clone();
    let startup = std::thread::spawn(move || {
        let mut planner = component_planner(&startup_dir, &["authority", "sidecar"]);
        let mut index = 0;
        spawn_stack_from_plan(
            &topology(&["authority", "sidecar"]),
            |context| {
                let mut spec = planner(context)?;
                if index == 0 {
                    spec.command
                        .env(CHILD_RELEASE, startup_dir.join("authority.release"))
                        .env(CHILD_BLOCK_PIDFILE, startup_dir.join("sidecar.pid"));
                }
                index += 1;
                Ok::<_, std::convert::Infallible>(spec)
            },
            &startup_dir,
            fast_timeouts(),
        )
    });
    wait_for_file(&state_dir.join("authority.pid"));
    let authority_pid = read_pidfile(&state_dir.join("authority.pid"));
    let cleanup = ProcessCleanup::new([authority_pid]);
    std::fs::write(state_dir.join("authority.release"), []).expect("release authority");

    let Err(error) = startup.join().expect("join startup") else {
        panic!("pidfile publication unexpectedly succeeded");
    };

    let StartError::Rollback {
        operation,
        rollback,
    } = error
    else {
        panic!("pidfile failure did not report explicit rollback failure");
    };
    assert!(matches!(*operation, StartError::Orchestrator(_)));
    assert!(rollback.processes_stopped());
    assert_process_absent(authority_pid);
    cleanup.disarm();
    std::fs::remove_dir(state_dir.join("sidecar.pid")).expect("remove pidfile blocker");
    stop_components(
        &state_dir,
        Duration::ZERO,
        &topology(&["authority", "sidecar"]),
    )
    .expect("clean retained state");
    assert!(!state_dir.join("stack.lock").exists());
    assert!(!state_dir.join("authority.pid").exists());
    assert!(!state_dir.join("authority.listen").exists());
    assert!(!state_dir.join("sidecar.listen").exists());
}
