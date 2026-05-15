//! Embedded `developer` policy profile — Spec v0.5 §5.1 verbatim.
//!
//! NOT INTENDED FOR PRODUCTION. NOT INTENDED FOR SHARED HOSTS.

pub const DEVELOPER_CEDAR: &str = r#"// =============================================================================
// firma developer profile — minimal default policy bundle
//
// NOT INTENDED FOR PRODUCTION. NOT INTENDED FOR SHARED HOSTS.
//
// This file is materialised by an autostarted Mini Authority on first boot
// when `firma run` is invoked in zero-config mode (no `[authority]` section
// in the user config, and the user answered `y` to the bootstrap prompt).
//
// The default rule is deny-by-default. Every outbound agent call is blocked
// until an operator adds explicit `permit(...)` rules. See
// `docs/policies/examples/` for sample shapes, and run
// `firma monitor --only-deny` to discover which action classes your agent
// is attempting.
// =============================================================================

forbid(principal, action, resource);

// Example of a real permit (commented). Copy, narrow the principal /
// action / resource set, and uncomment once you understand the surface.
//
// permit(
//     principal,
//     action == Action::"communication.external.send",
//     resource
// ) when {
//     resource.host == "api.example.com" &&
//     resource.path like "/v1/messages*"
// };
"#;
