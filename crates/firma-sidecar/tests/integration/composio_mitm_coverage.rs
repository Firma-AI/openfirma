//! Startup coverage checks for Composio HTTPS MITM interception.

use firma_http::Method;
use firma_sidecar::config::{HttpsMitmConfig, MappingRuleConfig, MappingRulesFile};
use firma_sidecar::startup::{composio_mitm_coverage_warnings, mapping_references_composio_hosts};

fn covering_config() -> HttpsMitmConfig {
    HttpsMitmConfig {
        intercept_hosts: vec![
            "app.composio.dev".to_string(),
            "backend.composio.dev".to_string(),
        ],
        strict_hosts: vec![
            "app.composio.dev".to_string(),
            "backend.composio.dev".to_string(),
        ],
        bypass_hosts: Vec::new(),
        ..HttpsMitmConfig::default()
    }
}

fn rule(host: &str) -> MappingRuleConfig {
    MappingRuleConfig {
        method: Some(Method::POST),
        host: host.to_string(),
        path: Some("/*".to_string()),
        action_class: "communication.external.send".to_string(),
    }
}

/// The opt-in signal for the coverage check must recognize every host form a
/// mapping rule can legally use: exact names, case variants, ports, trailing
/// dots, and the normalizer's glob language including mid-string wildcards
/// and the bare catch-all (which does govern Composio traffic at runtime).
#[test]
fn mapping_reference_detection_handles_pattern_and_port_forms() {
    for host in [
        "backend.composio.dev",
        "BACKEND.Composio.DEV",
        "*.composio.dev",
        "backend.composio.dev.",
        "backend.composio.dev:443",
        "backend.composio.dev:*",
        "backend.composio.dev:8*",
        "backend.*",
        "*composio.dev",
        "backend.composio.*",
        "*",
    ] {
        assert!(
            mapping_references_composio_hosts(&MappingRulesFile {
                rules: vec![rule(host)],
            }),
            "{host} must count as a Composio reference"
        );
    }
    assert!(!mapping_references_composio_hosts(&MappingRulesFile {
        rules: vec![
            rule("api.github.com"),
            rule("*.github.com"),
            rule("composio.dev.attacker.example"),
        ],
    }));
}

/// The mapping file shipped for Composio must trigger the coverage check.
#[test]
fn shipped_composio_mapping_opts_into_the_coverage_check() -> anyhow::Result<()> {
    let rules: MappingRulesFile =
        toml::from_str(include_str!("../../config/mappings/composio.toml"))?;
    assert!(mapping_references_composio_hosts(&rules));
    Ok(())
}

#[test]
fn full_strict_coverage_produces_no_warnings() {
    assert_eq!(
        composio_mitm_coverage_warnings(&covering_config()),
        Vec::<String>::new()
    );
}

#[test]
fn wildcard_patterns_count_as_coverage() {
    let config = HttpsMitmConfig {
        intercept_hosts: vec!["*.composio.dev".to_string()],
        strict_hosts: vec!["*.composio.dev".to_string()],
        bypass_hosts: Vec::new(),
        ..HttpsMitmConfig::default()
    };
    assert_eq!(
        composio_mitm_coverage_warnings(&config),
        Vec::<String>::new()
    );
}

#[test]
fn inactive_mitm_warns_once() {
    let config = HttpsMitmConfig {
        enabled: false,
        ..covering_config()
    };
    let warnings = composio_mitm_coverage_warnings(&config);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("HTTPS MITM is inactive"));
}

#[test]
fn bypassed_composio_host_warns() {
    let config = HttpsMitmConfig {
        bypass_hosts: vec!["backend.composio.dev".to_string()],
        ..covering_config()
    };
    let warnings = composio_mitm_coverage_warnings(&config);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("backend.composio.dev"));
    assert!(warnings[0].contains("bypass_hosts"));
}

#[test]
fn unintercepted_composio_hosts_warn_per_host() {
    let config = HttpsMitmConfig {
        intercept_hosts: vec!["api.github.com".to_string()],
        strict_hosts: vec!["api.github.com".to_string()],
        bypass_hosts: Vec::new(),
        ..HttpsMitmConfig::default()
    };
    let warnings = composio_mitm_coverage_warnings(&config);
    assert_eq!(warnings.len(), 2);
    assert!(warnings.iter().any(|w| w.contains("backend.composio.dev")));
    assert!(warnings.iter().any(|w| w.contains("app.composio.dev")));
    assert!(warnings.iter().all(|w| w.contains("intercept_hosts")));
}

#[test]
fn intercepted_but_non_strict_composio_host_warns() {
    let config = HttpsMitmConfig {
        strict_hosts: vec!["app.composio.dev".to_string()],
        ..covering_config()
    };
    let warnings = composio_mitm_coverage_warnings(&config);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("backend.composio.dev"));
    assert!(warnings[0].contains("strict_hosts"));
}
