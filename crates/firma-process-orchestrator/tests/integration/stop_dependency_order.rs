//! Dependency-sequential teardown regressions.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentSpec, LifecycleTimeouts, RunningStack, StackTopology, spawn_stack_from_plan,
};

use crate::support::wait_for_file;

#[test]
fn authority_is_not_signalled_until_sidecar_is_collected() {
    let dir = tempfile::tempdir().expect("state dir");
    let release = dir.path().join("release-sidecar");
    let sidecar_stopping = dir.path().join("sidecar-stopping");
    let authority_signal = dir.path().join("authority-signal");
    let mut stack = spawn_ordered_stack(
        dir.path(),
        &release,
        &sidecar_stopping,
        &authority_signal,
        false,
    );

    let release_thread = std::thread::spawn({
        let authority_signal = authority_signal.clone();
        move || {
            wait_for_file(&sidecar_stopping);
            assert!(
                !authority_signal.exists(),
                "authority was signalled while sidecar teardown was blocked"
            );
            std::fs::write(release, []).expect("release sidecar shutdown");
        }
    });

    let outcome = stack
        .shutdown(Duration::from_secs(2))
        .expect("ordered shutdown");
    release_thread.join().expect("join release thread");
    assert_eq!(read_marker(&authority_signal), "ordered");
    assert!(!outcome.forced);
}

#[test]
fn stuck_sidecar_consumes_the_single_grace_period() {
    let dir = tempfile::tempdir().expect("state dir");
    let release = dir.path().join("unused-release");
    let sidecar_stopping = dir.path().join("sidecar-stopping");
    let authority_signal = dir.path().join("authority-signal");
    let mut stack = spawn_ordered_stack(
        dir.path(),
        &release,
        &sidecar_stopping,
        &authority_signal,
        true,
    );
    let grace = Duration::from_secs(1);

    let started = Instant::now();
    let outcome = stack.shutdown(grace).expect("forced ordered shutdown");
    let elapsed = started.elapsed();

    assert!(outcome.forced, "stuck sidecar did not require escalation");
    if authority_signal.exists() {
        assert_eq!(read_marker(&authority_signal), "ordered");
    }
    assert!(
        elapsed >= grace,
        "shutdown did not spend the shared grace period: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_750),
        "shutdown appears to grant grace per component: {elapsed:?}"
    );
}

fn spawn_ordered_stack(
    state_dir: &Path,
    release: &Path,
    sidecar_stopping: &Path,
    authority_signal: &Path,
    stuck_sidecar: bool,
) -> RunningStack {
    let topology = StackTopology::new(["authority", "sidecar"]).expect("fixture topology");
    let listeners = [reserve_listener(), reserve_listener()];
    let addresses = listeners
        .each_ref()
        .map(|listener| listener.local_addr().expect("readiness address"));
    let sidecar_pidfile = state_dir.join("sidecar.pid");
    let authority_ready = state_dir.join("authority-ready");
    let sidecar_ready = state_dir.join("sidecar-ready");

    let mut authority = Command::new("sh");
    if stuck_sidecar {
        authority
            .arg("-c")
            .arg("trap '' TERM; printf ready > \"$AUTHORITY_READY.tmp\"; mv \"$AUTHORITY_READY.tmp\" \"$AUTHORITY_READY\"; exec sleep 3600")
            .env("AUTHORITY_READY", &authority_ready);
    } else {
        authority
            .arg("-c")
            .arg("trap 'if kill -0 -$(cat \"$SIDECAR_PIDFILE\") 2>/dev/null; then printf overlap; else printf ordered; fi > \"$AUTHORITY_SIGNAL\"; exit 0' TERM; printf ready > \"$AUTHORITY_READY.tmp\"; mv \"$AUTHORITY_READY.tmp\" \"$AUTHORITY_READY\"; while :; do sleep 0.05; done")
            .env("SIDECAR_PIDFILE", sidecar_pidfile)
            .env("AUTHORITY_READY", &authority_ready)
            .env("AUTHORITY_SIGNAL", authority_signal);
    }
    let mut sidecar = Command::new("sh");
    if stuck_sidecar {
        sidecar
            .arg("-c")
            .arg("trap '' TERM; printf ready > \"$SIDECAR_READY.tmp\"; mv \"$SIDECAR_READY.tmp\" \"$SIDECAR_READY\"; exec sleep 3600")
            .env("SIDECAR_READY", &sidecar_ready);
    } else {
        sidecar
            .arg("-c")
            .arg("trap 'printf stopping > \"$SIDECAR_STOPPING\"; while [ ! -f \"$SIDECAR_RELEASE\" ]; do sleep 0.01; done; exit 0' TERM; printf ready > \"$SIDECAR_READY.tmp\"; mv \"$SIDECAR_READY.tmp\" \"$SIDECAR_READY\"; while :; do sleep 1; done")
            .env("SIDECAR_STOPPING", sidecar_stopping)
            .env("SIDECAR_RELEASE", release)
            .env("SIDECAR_READY", &sidecar_ready);
    }
    let mut commands = [authority, sidecar].into_iter();
    let mut index = 0;
    let stack = spawn_stack_from_plan(
        &topology,
        |_| {
            let spec = ComponentSpec {
                command: commands.next().expect("component command"),
                readiness: firma_process_orchestrator::Readiness::Configured(
                    firma_process_orchestrator::ComponentEndpoint::Tcp(addresses[index]),
                ),
            };
            index += 1;
            Ok::<_, std::convert::Infallible>(spec)
        },
        state_dir,
        LifecycleTimeouts::default(),
    )
    .expect("spawn ordered stack");
    assert_eq!(read_marker(&authority_ready), "ready");
    assert_eq!(read_marker(&sidecar_ready), "ready");
    drop(listeners);
    stack
}

fn reserve_listener() -> std::net::TcpListener {
    std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve readiness address")
}

fn read_marker(path: &Path) -> String {
    wait_for_file(path);
    std::fs::read_to_string(path).expect("read marker")
}
