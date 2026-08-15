use firma_process_orchestrator::{
    ComponentSpec, LifecycleTimeouts, OrchestratorError, StackTopology, StartError,
    spawn_stack_from_plan,
};
use firma_test_helpers::process_fixture;
use std::net::{SocketAddr, TcpListener};
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
    let fixture_addr = free_fixture_addr();
    let mut command = Some(TcpListenerFixture::at(fixture_addr).command());
    let mut stack = spawn_stack_from_plan(
        &topology,
        |_| {
            Ok::<_, std::convert::Infallible>(ComponentSpec {
                command: command.take().expect("single component planned once"),
                readiness: firma_process_orchestrator::Readiness::Configured(
                    firma_process_orchestrator::ComponentEndpoint::Tcp(fixture_addr),
                ),
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

#[derive(serde::Deserialize, serde::Serialize)]
struct TcpListenerFixture {
    addr: SocketAddr,
}

impl TcpListenerFixture {
    fn at(addr: SocketAddr) -> Self {
        Self { addr }
    }

    fn command(self) -> std::process::Command {
        explicit_executable_fixture(self)
    }

    fn run(self) {
        let listener = TcpListener::bind(self.addr).expect("bind fixture listener");
        loop {
            let _connection = listener.accept().expect("accept readiness connection");
        }
    }
}

process_fixture! {
    fn explicit_executable_fixture(fixture: TcpListenerFixture) {
        fixture.run();
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
