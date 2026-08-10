use firma_process_orchestrator::{
    ComponentSpec, LifecycleTimeouts, OrchestratorError, StackTopology, StartError,
    spawn_stack_from_plan,
};
use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::time::Duration;

fn free_fixture_addr() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve fixture port");
    listener.local_addr().expect("fixture address")
}

#[test]
fn topology_rejects_unsafe_and_duplicate_names() {
    for name in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a:b",
        "worker.",
        "worker ",
        "CON",
        "con.log",
        "PrN.txt",
        "AUX",
        "nul.data",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt9.txt",
        "COM¹",
        "com².log",
        "CoM³.txt",
        "LPT¹",
        "lpt².log",
        "LpT³.txt",
    ] {
        let error = StackTopology::new([name]).expect_err("name must be rejected");
        assert!(matches!(
            error,
            OrchestratorError::InvalidComponentName { name: rejected } if rejected == name
        ));
    }

    let error = StackTopology::new(["worker", "worker"]).expect_err("duplicate must fail");
    assert!(matches!(
        error,
        OrchestratorError::DuplicateComponentName { name } if name == "worker"
    ));

    let error =
        StackTopology::new(["Worker", "worker"]).expect_err("case-insensitive duplicate must fail");
    assert!(matches!(
        error,
        OrchestratorError::DuplicateComponentName { name } if name == "worker"
    ));
}

#[test]
fn component_spec_explicit_executable_is_used() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let topology = StackTopology::new(["listener"]).expect("valid topology");
    let executable = std::env::current_exe().expect("integration test executable");
    let fixture_addr = free_fixture_addr();
    let mut command = Command::new(executable);
    command
        .args([
            "--exact",
            "startup_contract::explicit_executable_fixture",
            "--ignored",
        ])
        .env("FIRMA_TEST_FIXTURE_ADDR", fixture_addr.to_string());
    let mut command = Some(command);
    let mut stack = spawn_stack_from_plan(
        &topology,
        |_| {
            Ok::<_, std::convert::Infallible>(ComponentSpec {
                command: command.take().expect("single component planned once"),
                readiness: firma_process_orchestrator::Readiness::ConfiguredTcp(fixture_addr),
            })
        },
        state_dir.path(),
        LifecycleTimeouts::default(),
    )
    .expect("explicit executable starts and becomes ready");

    stack
        .shutdown(Duration::from_secs(2))
        .expect("running stack shuts fixture down");
}

#[test]
#[ignore = "spawned as a process-lifecycle fixture"]
fn explicit_executable_fixture() {
    let addr = std::env::var("FIRMA_TEST_FIXTURE_ADDR")
        .expect("fixture address environment variable")
        .parse::<SocketAddr>()
        .expect("valid fixture address");
    let listener = TcpListener::bind(addr).expect("bind fixture listener");
    loop {
        let _connection = listener.accept().expect("accept readiness connection");
    }
}

#[test]
fn topology_controls_staged_planner_cardinality() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let topology = StackTopology::new(["first", "second"]).expect("valid topology");
    let mut calls = 0;
    let result = spawn_stack_from_plan(
        &topology,
        |_| {
            calls += 1;
            Err::<ComponentSpec, _>("stop before spawn")
        },
        state_dir.path(),
        LifecycleTimeouts::default(),
    );

    assert!(matches!(result, Err(StartError::Plan("stop before spawn"))));
    assert_eq!(calls, 1, "planner is called lazily in topology order");
    assert!(!state_dir.path().join("first.pid").exists());
    assert!(!state_dir.path().join("second.pid").exists());
}
