use firma_secret_provider::{HttpIntegrationSpec, HttpMatcherRule};

use crate::support::{json, regex};

fn spec(matchers: Vec<HttpMatcherRule>) -> HttpIntegrationSpec {
    HttpIntegrationSpec {
        provider_id: String::from("aws-secrets-manager"),
        host: String::from("secretsmanager.*.amazonaws.com"),
        matchers,
    }
}

#[test]
fn matcher_resolves_by_exact_path() {
    let spec = spec(vec![
        HttpMatcherRule {
            path: Some(String::from("/list")),
            matcher: json("$[*]", "$.value", "$.key"),
        },
        HttpMatcherRule {
            path: Some(String::from("/get")),
            matcher: json("$", "$.value", "$.key"),
        },
    ]);

    assert_eq!(
        spec.matcher_for("/list"),
        Some(&json("$[*]", "$.value", "$.key"))
    );
    assert_eq!(
        spec.matcher_for("/get"),
        Some(&json("$", "$.value", "$.key"))
    );
}

#[test]
fn matcher_resolves_by_path_glob() {
    let spec = spec(vec![HttpMatcherRule {
        path: Some(String::from("/v1/secrets/*")),
        matcher: regex("(?P<name>.+)=(?P<value>.+)"),
    }]);

    assert!(spec.matcher_for("/v1/secrets/get/abc123").is_some());
    assert!(spec.matcher_for("/v1/other").is_none());
}

#[test]
fn fallback_rule_applies_when_no_specific_path_matches() {
    let spec = spec(vec![
        HttpMatcherRule {
            path: Some(String::from("/list")),
            matcher: json("$[*]", "$.value", "$.key"),
        },
        HttpMatcherRule {
            path: None,
            matcher: json("$", "$.value", "$.key"),
        },
    ]);

    assert_eq!(
        spec.matcher_for("/list"),
        Some(&json("$[*]", "$.value", "$.key"))
    );
    assert_eq!(
        spec.matcher_for("/anything/else"),
        Some(&json("$", "$.value", "$.key"))
    );
}

#[test]
fn no_match_returns_none_without_a_fallback() {
    let spec = spec(vec![HttpMatcherRule {
        path: Some(String::from("/list")),
        matcher: json("$[*]", "$.value", "$.key"),
    }]);

    assert!(spec.matcher_for("/get").is_none());
}
