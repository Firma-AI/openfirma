//! Deterministic black-box tests for the compiled `firma` CLI.
//!
//! Product behavior in this target must be exercised through
//! `CARGO_BIN_EXE_firma`, not by calling workspace production APIs directly.

pub use firma_config_loader::{CONFIG_DIR_NAME, CONFIG_FILE_NAME};

fn firma_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for the [[bin]] under test.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_firma"))
}

mod authority_client_cert;
mod authority_fixture;
mod authority_keygen;
mod authority_mapping_watch;
mod cli_help;
mod cli_parsing;
mod config_fixture;
mod config_selection;
mod doctor;
mod firma_config;
mod login;
mod logout;
mod managed_configuration;
mod mapping_compatibility;
mod monitor_audit_stream;
mod monitor_decoupled;
mod policy_cli;
mod run_agent;
mod run_authority_flags;
mod run_autostart_flags;
mod run_implicit_init_prompt;
mod sandbox_identity;
mod sidecar_endpoint_publication;
mod sidecar_invalid_config;
mod sidecar_readiness_gate;
mod sidecar_runtime_credential;
mod sidecar_seed_e2e;
mod sidecar_start_scaffold;
mod sidecar_startup_contract;
mod sidecar_status_cli;
mod stack_lifecycle;
mod vscode_mapping;
