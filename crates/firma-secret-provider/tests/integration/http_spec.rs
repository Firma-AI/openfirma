use firma_core::SecretMatcher;
use firma_secret_provider::{
    MatcherCompiler, MatcherError, MatchingResolution,
    non_empty::NonEmptyString,
    spec::http::{HttpIntegrationSpec, HttpMatcherRule, PathAndMatcher, PathOnly},
};

use crate::support::{json, regex};

fn spec(matchers: Vec<HttpMatcherRule<SecretMatcher>>) -> HttpIntegrationSpec<SecretMatcher> {
    HttpIntegrationSpec {
        provider_id: String::from("aws-secrets-manager"),
        host: String::from("secretsmanager.*.amazonaws.com"),
        matchers,
    }
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn safe(path: &str) -> HttpMatcherRule<SecretMatcher> {
    HttpMatcherRule::SafeCommand(PathOnly {
        path: NonEmptyString::new(String::from(path)).expect("non-empty"),
    })
}

#[expect(clippy::expect_used, reason = "this is a test")]
fn blocked(path: &str) -> HttpMatcherRule<SecretMatcher> {
    HttpMatcherRule::BlockedCommand(PathOnly {
        path: NonEmptyString::new(String::from(path)).expect("non-empty"),
    })
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

#[test]
fn safe_command_matches_path_as_pass_through() {
    let spec = spec(vec![
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(String::from("/get")),
            matcher: json("$", "$.value", "$.key"),
        }),
        safe("/list"),
    ]);

    assert_eq!(spec.matcher_for("/list"), MatchingResolution::PassThrough);
    assert_eq!(
        spec.matcher_for("/get"),
        MatchingResolution::Matcher(&json("$", "$.value", "$.key"))
    );
}

#[test]
fn blocked_command_takes_precedence_over_sensitive() {
    // A blocked command is checked first, so it must win over a sensitive
    // matcher that would otherwise redact the same path.
    let spec = spec(vec![
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(String::from("/admin/*")),
            matcher: json("$", "$.value", "$.key"),
        }),
        blocked("/admin/delete"),
    ]);

    std::assert_matches!(
        spec.matcher_for("/admin/delete"),
        MatchingResolution::Blocked
    );
    std::assert_matches!(
        spec.matcher_for("/admin/list"),
        MatchingResolution::Matcher(_)
    );
}

#[test]
fn safe_command_fallback_path_none_is_rejected_at_deserialization() {
    // `PathOnly` requires a non-empty path, so an HTTP config cannot express
    // a bare `PassThrough`/`Blocked` rule that matches every path.
    let error = serde_json::from_str::<HttpMatcherRule<SecretMatcher>>(
        r#"{
        "type": "safe_command",
        "path": ""
    }"#,
    )
    .expect_err("empty safe path must fail to deserialize");
    assert_eq!(error.classify(), serde_json::error::Category::Data);
}

#[test]
fn compile_produces_compiled_matchers() {
    let spec = spec(vec![
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: Some(String::from("/list")),
            matcher: json("$[*]", "$.value", "$.key"),
        }),
        HttpMatcherRule::SensitiveCommand(PathAndMatcher {
            path: None,
            matcher: regex("(?P<name>.+)=(?P<value>.+)"),
        }),
        safe("/health"),
        blocked("/delete"),
    ]);

    let compiled = spec
        .compile()
        .unwrap_or_else(|error| panic!("valid spec must compile: {error}"));
    assert_eq!(compiled.host, "secretsmanager.*.amazonaws.com");
    assert_eq!(compiled.matchers.len(), 4);
    std::assert_matches!(
        compiled.matcher_for("/list"),
        MatchingResolution::Matcher(_)
    );
}

#[test]
fn compile_rejects_invalid_matcher() {
    let spec = spec(vec![HttpMatcherRule::SensitiveCommand(PathAndMatcher {
        path: Some(String::from("/get")),
        matcher: json("$[", "$.value", "$.key"),
    })]);

    let error = spec
        .compile()
        .expect_err("invalid matcher must fail compile");
    std::assert_matches!(
        error,
        MatcherError::JsonPath { path, .. } if path == "$["
    );
}
