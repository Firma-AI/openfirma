use firma_core::SecretMatcher;
use firma_secret_provider::{
    MatchingResolution,
    spec::http::{HttpIntegrationSpec, HttpMatcherRule, PathAndMatcher},
};

use crate::support::{json, regex};

fn spec(matchers: Vec<HttpMatcherRule<SecretMatcher>>) -> HttpIntegrationSpec<SecretMatcher> {
    HttpIntegrationSpec {
        provider_id: String::from("aws-secrets-manager"),
        host: String::from("secretsmanager.*.amazonaws.com"),
        matchers,
    }
}

#[test]
fn matcher_resolves_by_exact_path() {
    let spec = spec(vec![
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(String::from("/list")),
            matcher: json("$[*]", "$.value", "$.key"),
        }),
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(String::from("/get")),
            matcher: json("$", "$.value", "$.key"),
        }),
    ]);

    assert_eq!(
        spec.matcher_for("/list"),
        MatchingResolution::Matcher(&json("$[*]", "$.value", "$.key"))
    );
    assert_eq!(
        spec.matcher_for("/get"),
        MatchingResolution::Matcher(&json("$", "$.value", "$.key"))
    );
}

#[test]
fn matcher_resolves_by_path_glob() {
    let spec = spec(vec![HttpMatcherRule::SensitiveCommand(PathAndMatcher {
        path: Some(String::from("/v1/secrets/*")),
        matcher: regex("(?P<name>.+)=(?P<value>.+)"),
    })]);

    std::assert_matches!(
        spec.matcher_for("/v1/secrets/get/abc123"),
        MatchingResolution::Matcher(_)
    );
    std::assert_matches!(spec.matcher_for("/v1/other"), MatchingResolution::Blocked);
}

#[test]
fn fallback_rule_applies_when_no_specific_path_matches() {
    let spec = spec(vec![
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(String::from("/list")),
            matcher: json("$[*]", "$.value", "$.key"),
        }),
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: None,
            matcher: json("$", "$.value", "$.key"),
        }),
    ]);

    assert_eq!(
        spec.matcher_for("/list"),
        MatchingResolution::Matcher(&json("$[*]", "$.value", "$.key"))
    );
    assert_eq!(
        spec.matcher_for("/anything/else"),
        MatchingResolution::Matcher(&json("$", "$.value", "$.key"))
    );
}

#[test]
fn no_match_returns_none_without_a_fallback() {
    let spec = spec(vec![HttpMatcherRule::SensitiveCommand(PathAndMatcher {
        path: Some(String::from("/list")),
        matcher: json("$[*]", "$.value", "$.key"),
    })]);

    std::assert_matches!(spec.matcher_for("/get"), MatchingResolution::Blocked);
}
