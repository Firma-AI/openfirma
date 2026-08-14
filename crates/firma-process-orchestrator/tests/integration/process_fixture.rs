//! Typed configuration transport for tests that re-execute the integration
//! test binary as a managed child process. Configuration is encoded as JSON,
//! so fixture configuration must model paths with `camino::Utf8PathBuf` rather
//! than `std::path::PathBuf`.

use std::process::Command;

use serde::Serialize;
use serde::de::DeserializeOwned;

const CONFIG_ENV: &str = "FIRMA_PROCESS_FIXTURE_CONFIG";

#[expect(
    clippy::redundant_pub_crate,
    reason = "macro expansions in sibling modules call this helper"
)]
pub(crate) fn command<T>(test_name: &str, config: &T) -> Command
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
pub(crate) fn config<T>() -> T
where
    T: DeserializeOwned,
{
    let encoded = std::env::var(CONFIG_ENV).expect("process fixture configuration");
    serde_json::from_str(&encoded).expect("deserialize process fixture configuration")
}

macro_rules! process_fixture {
    ($(#[$attribute:meta])* fn $name:ident($config:ident: $config_type:ty) $body:block) => {
        $(#[$attribute])*
        fn $name($config: $config_type) -> std::process::Command {
            crate::process_fixture::command(
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
                let $config: $config_type = crate::process_fixture::config();
                $body
            }
        }
    };
}
