//! Load-time normalization of mapping-rule host patterns.

use firma_http::Method;
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::normalizer::MatchResult;
use firma_sidecar::pipeline::{ActionClassRegistry, MappingTable};

fn rule(host: &str) -> MappingRuleConfig {
    MappingRuleConfig {
        method: Some(Method::GET),
        host: host.to_string(),
        path: Some("/repos/*".to_string()),
        action_class: "communication.external.read".to_string(),
    }
}

/// A rule host written with case or a trailing dot must still match runtime
/// hosts, which arrive lowercased with the trailing dot stripped; without
/// load-time normalization such a rule is dead.
#[test]
fn rule_hosts_are_normalized_at_load_time() -> anyhow::Result<()> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("API.GitHub.COM.")],
        },
        &ActionClassRegistry::v0_1(),
        false,
    )?;

    assert!(matches!(
        table.find_match(&Method::GET, "api.github.com", "/repos/x"),
        MatchResult::Matched(_)
    ));
    Ok(())
}

/// Default ports are stripped from rule hosts like runtime hosts, while a
/// nonstandard port is preserved and still matches ported traffic.
#[test]
fn rule_host_ports_mirror_runtime_normalization() -> anyhow::Result<()> {
    let registry = ActionClassRegistry::v0_1();
    let default_port = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.github.com:443")],
        },
        &registry,
        false,
    )?;
    assert!(matches!(
        default_port.find_match(&Method::GET, "api.github.com", "/repos/x"),
        MatchResult::Matched(_)
    ));

    let nonstandard_port = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.github.com:8443")],
        },
        &registry,
        false,
    )?;
    assert!(matches!(
        nonstandard_port.find_match(&Method::GET, "api.github.com:8443", "/repos/x"),
        MatchResult::Matched(_)
    ));
    assert!(matches!(
        nonstandard_port.find_match(&Method::GET, "api.github.com", "/repos/x"),
        MatchResult::NotProtected
    ));
    Ok(())
}

/// Degenerate wildcard hosts that would silently normalize into the bare
/// catch-all are rejected at validation.
#[test]
fn degenerate_catch_all_host_patterns_are_rejected() {
    for host in ["*.", "*:443"] {
        let result = MappingTable::from_config(
            &MappingRulesFile {
                rules: vec![rule(host)],
            },
            &ActionClassRegistry::v0_1(),
            false,
        );
        assert!(result.is_err(), "{host} must be rejected at validation");
    }
}

/// Case or trailing-dot variants of the same rule are the same rule; the
/// duplicate check compares normalized hosts so they fail at startup.
#[test]
fn duplicate_detection_compares_normalized_hosts() {
    let result = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.github.com"), rule("API.GITHUB.COM.")],
        },
        &ActionClassRegistry::v0_1(),
        false,
    );

    assert!(result.is_err());
}
