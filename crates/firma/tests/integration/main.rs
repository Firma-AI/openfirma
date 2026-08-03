//! Deterministic black-box tests for the compiled `firma` CLI.
//!
//! Product behavior in this target must be exercised through
//! `CARGO_BIN_EXE_firma`, not by calling workspace production APIs directly.

const CONFIG_DIR_NAME: &str = ".firma";
const CONFIG_FILE_NAME: &str = "firma.toml";

mod authority_keygen;
mod child_process_escape;
mod cli_help;
mod cli_parsing;
mod doctor;
mod e2e_startup;
mod firma_config;
mod monitor_audit_stream;
mod monitor_decoupled;
mod policy_cli;
mod run_authority_flags;
mod run_autostart_flags;
mod run_echo_smoke;
mod run_implicit_init_prompt;
mod sandbox_identity;
mod sidecar_invalid_config;
mod sidecar_readiness_gate;
mod sidecar_seed_e2e;
mod sidecar_start_scaffold;
mod sidecar_startup_contract;
mod sidecar_status_cli;
mod stack_lifecycle;
mod vscode_mapping;
