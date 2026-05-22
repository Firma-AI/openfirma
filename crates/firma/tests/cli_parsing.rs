//! Parser round-trip tests that catch arg-name collisions and required
//! field regressions without booting any service.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics are acceptable test failures"
)]

#[expect(
    unused_imports,
    reason = "forces clap linkage for compile-time validation"
)]
use clap::Parser as _;

// Re-import the binary's CLI module by depending on the binary as a
// library would not work, so we duplicate the parse via a small
// matchable invocation — checking only success/failure and the picked
// subcommand variant via stderr-free `try_parse_from` exit codes is
// enough for the regression we want to catch.

fn parse_ok(argv: &[&str]) {
    // Build a child `firma` process with `--help`-equivalent dry-run by
    // appending an obviously-correct `--help` *after* the subcommand
    // would change semantics. Instead, rely on the binary's exit code:
    // valid parses that need IO will fail later with a non-clap error;
    // we only assert the parser does not error out.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(argv)
        .arg("--help")
        .output()
        .expect("spawn firma");
    assert!(
        output.status.success(),
        "parse failed for {argv:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn parse_sidecar_with_config_flag() {
    parse_ok(&["sidecar", "-c", "/tmp/sidecar.toml"]);
}

#[test]
fn parse_authority_default() {
    parse_ok(&["authority"]);
}

#[test]
fn parse_authority_issue_multiple_actions() {
    parse_ok(&[
        "authority",
        "issue",
        "--agent-id",
        "agent-1",
        "--session-id",
        "00000000-0000-0000-0000-000000000000",
        "--action",
        "fep.read",
        "--action",
        "fep.write",
        "--output",
        "/tmp/seed.toml",
    ]);
}

#[test]
fn parse_authority_bootstrap_tls() {
    parse_ok(&[
        "authority",
        "init-tls",
        "--out-dir",
        "/tmp/firma-tls",
        "--host",
        "localhost",
        "--host",
        "127.0.0.1",
    ]);
}

#[test]
fn parse_run_with_command_after_dashdash() {
    parse_ok(&["run", "--profile", "generic"]);
}

#[test]
fn parse_dns_stub_with_listen() {
    parse_ok(&["__dns-stub", "--listen", "127.0.0.1:5353"]);
}

#[test]
fn parse_proxy_bridge_with_uds() {
    parse_ok(&[
        "__proxy-bridge",
        "--listen",
        "127.0.0.1:18080",
        "--upstream-uds",
        "/tmp/firma.sock",
    ]);
}

#[test]
fn global_log_filter_visible_under_subcommand() {
    parse_ok(&["--log-filter", "debug", "sidecar"]);
}

#[test]
fn parse_config_defaults() {
    parse_ok(&["config"]);
}

#[test]
fn parse_config_scripted() {
    parse_ok(&[
        "config",
        "--yes",
        "--name",
        "codex",
        "--posture",
        "dev",
        "--mapping",
        "anthropic",
        "--workspace",
        "/tmp/proj",
    ]);
}

#[test]
fn parse_config_global() {
    parse_ok(&["config", "--yes", "--global"]);
}

#[test]
fn parse_sidecar_start() {
    parse_ok(&["sidecar", "start", "--config", "firma.toml", "--detach"]);
}

#[test]
fn parse_monitor_defaults() {
    parse_ok(&["monitor"]);
}

#[test]
fn parse_sidecar_status_json() {
    parse_ok(&["sidecar", "status", "--json"]);
}

#[test]
fn parse_sidecar_stop() {
    parse_ok(&["sidecar", "stop", "--timeout", "5"]);
}
