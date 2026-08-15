//! Shared support for `OpenFirma` test suites.

#![allow(
    clippy::expect_used,
    reason = "fixture setup failures should fail the calling test immediately"
)]

use std::process::Command;

use serde::Serialize;
use serde::de::DeserializeOwned;

const CONFIG_ENV: &str = "FIRMA_PROCESS_FIXTURE_CONFIG";

/// Builds a command that re-executes the current test binary and selects one
/// ignored fixture test.
///
/// This is an implementation detail of [`process_fixture!`].
#[doc(hidden)]
pub fn process_fixture_command<T>(test_name: &str, config: &T) -> Command
where
    T: Serialize,
{
    let test_name = test_name
        .split_once("::")
        .map_or(test_name, |(_, unqualified)| unqualified);
    let mut command = Command::new(std::env::current_exe().expect("integration test executable"));
    command.args(["--exact", test_name, "--ignored"]).env(
        CONFIG_ENV,
        serde_json::to_string(config).expect("serialize process fixture configuration"),
    );
    command
}

/// Reads configuration supplied by [`process_fixture_command`].
///
/// This is an implementation detail of [`process_fixture!`].
#[doc(hidden)]
#[must_use]
pub fn process_fixture_config<T>() -> T
where
    T: DeserializeOwned,
{
    let encoded = std::env::var(CONFIG_ENV).expect("process fixture configuration");
    serde_json::from_str(&encoded).expect("deserialize process fixture configuration")
}

/// Renders a Unix shell script that executes a generated fixture command.
///
/// `setup` runs before the fixture command and can translate arguments from a
/// production CLI contract into environment variables consumed by the
/// fixture. The command's program, arguments, and environment must all be
/// UTF-8.
#[cfg(unix)]
#[must_use]
pub fn unix_fixture_script(command: &Command, setup: &str) -> String {
    fn quote(value: &std::ffi::OsStr) -> String {
        let value = value
            .to_str()
            .expect("process fixture shell value is UTF-8");
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    let mut script = String::from("#!/bin/sh\n");
    script.push_str(setup);
    if !setup.ends_with('\n') {
        script.push('\n');
    }
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            script.push_str("export ");
            script.push_str(&quote(name));
            script.push('=');
            script.push_str(&quote(value));
            script.push('\n');
        }
    }
    script.push_str("exec ");
    script.push_str(&quote(command.get_program()));
    for argument in command.get_args() {
        script.push(' ');
        script.push_str(&quote(argument));
    }
    script.push('\n');
    script
}

/// Declares an ignored test entry point and a typed launcher for a child
/// process.
///
/// The generated function returns a [`Command`] so the calling test can add
/// environment variables that are part of the behavior under test. Private
/// fixture configuration is transported as JSON instead. Use
/// `camino::Utf8PathBuf` rather than `std::path::PathBuf` for paths in that
/// configuration so the transport remains UTF-8-only.
#[macro_export]
macro_rules! process_fixture {
    ($(#[$attribute:meta])* fn $name:ident($config:ident: $config_type:ty) $body:block) => {
        $(#[$attribute])*
        fn $name($config: $config_type) -> std::process::Command {
            $crate::process_fixture_command(
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
                let $config: $config_type = $crate::process_fixture_config();
                $body
            }
        }
    };
    ($(#[$attribute:meta])* fn $name:ident() $body:block) => {
        $(#[$attribute])*
        fn $name() -> std::process::Command {
            $crate::process_fixture_command(
                concat!(module_path!(), "::", stringify!($name), "::run"),
                &(),
            )
        }

        $(#[$attribute])*
        mod $name {
            use super::*;

            #[test]
            #[ignore = "spawned as a process-lifecycle fixture"]
            fn run() {
                let (): () = $crate::process_fixture_config();
                $body
            }
        }
    };
}
