mod audit_buffer;
mod audit_replay;
mod audit_tls;
mod authority_ca_files;
mod authority_connect_addr;
mod authority_trust;
mod capability_reload;
mod composio_catalog;
mod composio_cedar;
mod composio_composite;
mod composio_mitm_coverage;
mod composio_protocol;
mod http_connector;
mod interceptor_startup;
mod local_exec_config;
mod managed_snapshots;
mod mapping_compatibility;
mod mapping_rules;
mod mitm_ca_material;
mod mitm_config;
mod pipeline_fixture;
mod policy_schema_compatibility;
mod query_redaction;
mod resource_host_rules;
mod revocation_token_id;
mod runtime_credential;
mod runtime_snapshot;
mod sandbox_identity;
mod secret_gateway_regressions;
mod state_defaults;
mod state_layout;

/// A run rejection for a Sidecar under test that stops through `exit`.
fn test_rejection(
    exit: tokio_util::sync::CancellationToken,
) -> firma_sidecar::authority_client::RunRejection {
    use firma_sidecar::authority_client::readiness::{ReadinessFlag, ReadinessState};
    let (readiness, _view) = ReadinessFlag::new(ReadinessState::default());
    firma_sidecar::authority_client::RunRejection::new(std::sync::Arc::new(readiness), exit)
}
