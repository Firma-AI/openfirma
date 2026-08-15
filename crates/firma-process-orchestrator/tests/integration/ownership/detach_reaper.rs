use super::*;

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
    let handle = start_detached(
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
    assert_eq!(
        handle
            .components()
            .map(|component| (component.name(), component.leader_pid().get()))
            .collect::<Vec<_>>(),
        [("authority", pids[0]), ("sidecar", pids[1])]
    );
    for component in handle.components() {
        #[cfg(unix)]
        let endpoint = match component.endpoint() {
            ComponentEndpoint::Tcp(endpoint) => endpoint,
            ComponentEndpoint::Unix(_) => unreachable!("fixture publishes TCP endpoints"),
        };
        #[cfg(windows)]
        let ComponentEndpoint::Tcp(endpoint) = component.endpoint();
        assert_ne!(endpoint.port(), 0);
    }
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
