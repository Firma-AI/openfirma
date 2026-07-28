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
