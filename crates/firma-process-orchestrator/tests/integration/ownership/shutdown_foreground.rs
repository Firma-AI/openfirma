use super::*;

#[test]
fn owned_shutdown_is_idempotent_and_ignores_pidfiles() {
    let dir = tempfile::tempdir().expect("state dir");
    let (mut stack, pids) = spawn_stack(dir.path(), &["authority", "sidecar"]);
    let handle = stack.handle().clone();
    let ordered: Vec<_> = handle
        .components()
        .map(firma_process_orchestrator::ComponentHandle::name)
        .collect();
    assert_eq!(ordered, ["authority", "sidecar"]);
    assert_eq!(
        handle
            .component("authority")
            .expect("authority handle")
            .leader_pid()
            .get(),
        pids[0]
    );
    assert!(handle.component("missing").is_none());
    std::fs::remove_file(dir.path().join("authority.pid")).expect("remove pidfile");
    std::fs::write(dir.path().join("sidecar.pid"), "not-a-pid\n").expect("corrupt pidfile");

    stack.shutdown(Duration::ZERO).expect("owned shutdown");
    let repeated = stack.shutdown(Duration::ZERO).expect("repeated shutdown");

    assert!(!repeated.forced);
    assert_eq!(handle.components().count(), 2);
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
