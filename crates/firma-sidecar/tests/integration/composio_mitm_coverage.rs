//! Startup coverage checks for Composio HTTPS MITM interception.

use firma_sidecar::config::HttpsMitmConfig;
use firma_sidecar::startup::composio_mitm_coverage_warnings;

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
