#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentSpec, RunningStack, StackTopology, spawn_stack_from_plan,
};

pub fn spawn_managed_component(
    state_dir: &Path,
    topology: &StackTopology,
    command: Command,
) -> RunningStack {
    let readiness_listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind readiness listener");
    let readiness_addr = readiness_listener.local_addr().expect("readiness address");
    let stack = spawn_stack_from_plan(
        topology,
        || {
            Ok::<_, std::convert::Infallible>(vec![ComponentSpec {
                command,
                readiness_addr,
            }])
        },
        state_dir,
    )
    .expect("spawn managed component");
    drop(readiness_listener);
    stack
}

pub fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}
