#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use firma_process_orchestrator::{
    ComponentSpec, LifecycleTimeouts, RunningStack, StackTopology, spawn_stack_from_plan,
};

pub fn spawn_managed_component(
    state_dir: &Path,
    topology: &StackTopology,
    command: Command,
) -> RunningStack {
    let readiness_listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind readiness listener");
    let readiness_addr = readiness_listener.local_addr().expect("readiness address");
    let mut command = Some(command);
    let stack = spawn_stack_from_plan(
        topology,
        |_| {
            Ok::<_, std::convert::Infallible>(ComponentSpec {
                command: command.take().expect("single component planned once"),
                readiness: firma_process_orchestrator::Readiness::Configured(
                    firma_process_orchestrator::ComponentEndpoint::Tcp(readiness_addr),
                ),
            })
        },
        state_dir,
        LifecycleTimeouts::default(),
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
