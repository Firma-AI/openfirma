use super::*;

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
    assert!(rollback.processes_stopped());
    assert!(matches!(
        rollback.into_orchestrator_error(),
        OrchestratorError::Platform(_)
    ));
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
fn detached_handle_reconstruction_rejects_replacement_generation() {
    let dir = tempfile::tempdir().expect("state dir");
    let result = start_detached(
        &topology(&["authority"]),
        dir.path(),
        fast_timeouts(),
        |generation| supervisor_command(dir.path(), generation, "attach-replacement"),
    );

    let Err(OrchestratorError::Platform(reason)) = result else {
        panic!("replacement generation must invalidate the detached handle");
    };
    assert_eq!(
        reason,
        "stack generation changed before detached handle reconstruction"
    );
    let replacement = std::fs::read_to_string(dir.path().join("replacement.generation"))
        .expect("read replacement generation");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("stack.lock")).expect("replacement lock"),
        replacement
    );
}
