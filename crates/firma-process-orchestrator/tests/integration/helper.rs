//! Support shared by multiple integration-test modules.

#[cfg(unix)]
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::time::{Duration, Instant};

use firma_process_orchestrator::StackTopology;
#[cfg(unix)]
use firma_process_orchestrator::{
    ComponentSpec, LifecycleTimeouts, RunningStack, spawn_stack_from_plan,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

const CONFIG_ENV: &str = "FIRMA_PROCESS_FIXTURE_CONFIG";

pub fn topology() -> StackTopology {
    StackTopology::new(["authority", "sidecar"]).expect("valid test topology")
}

#[cfg(unix)]
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

#[cfg(unix)]
pub fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{} missing", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "macro expansions in sibling modules call this helper"
)]
pub(crate) fn process_fixture_command<T>(test_name: &str, config: &T) -> Command
where
    T: Serialize,
{
    let test_name = test_name
        .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
        .unwrap_or(test_name);
    let mut command = Command::new(std::env::current_exe().expect("integration test executable"));
    command.args(["--exact", test_name, "--ignored"]).env(
        CONFIG_ENV,
        serde_json::to_string(config).expect("serialize process fixture configuration"),
    );
    command
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "macro expansions in sibling modules call this helper"
)]
pub(crate) fn process_fixture_config<T>() -> T
where
    T: DeserializeOwned,
{
    let encoded = std::env::var(CONFIG_ENV).expect("process fixture configuration");
    serde_json::from_str(&encoded).expect("deserialize process fixture configuration")
}

/// Declares an ignored test entry point and a typed launcher for a managed
/// child process. Configuration is encoded as JSON, so paths in fixture
/// configuration must use `camino::Utf8PathBuf`.
macro_rules! process_fixture {
    ($(#[$attribute:meta])* fn $name:ident($config:ident: $config_type:ty) $body:block) => {
        $(#[$attribute])*
        fn $name($config: $config_type) -> std::process::Command {
            crate::helper::process_fixture_command(
                concat!(module_path!(), "::", stringify!($name), "::run"),
                &$config,
            )
        }

        $(#[$attribute])*
        mod $name {
            use super::*;

            #[test]
            #[ignore = "spawned as a process-lifecycle fixture"]
            fn run() {
                let $config: $config_type = crate::helper::process_fixture_config();
                $body
            }
        }
    };
}
