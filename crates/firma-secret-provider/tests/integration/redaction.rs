use firma_core::SecretJsonSelectorScope;
use firma_secret_provider::{CompiledMatcher, MatcherError};

use crate::support::{json, json_with_metadata, selector};

#[test]
fn secret_does_not_leak_contents() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();
    let mut secrets = Vec::new();
    compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA"},{"key":"b","value":"BBB"}]"#,
            &mut |_, value, _, _| {
                secrets.push(value.to_string());
                String::new()
            },
        )
        .unwrap();
    assert_eq!(secrets, ["<secret>", "<secret>"]);
}

#[test]
fn hostless_uri_error_does_not_expose_domain_value() {
    let sensitive_domain = "/vault/path?token=super-secret";
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domain", SecretJsonSelectorScope::Record)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let output = format!(r#"[{{"key":"token","value":"AAA","domain":"{sensitive_domain}"}}]"#);
    let error = compiled
        .rewrite(output.as_bytes(), &mut |_, _, _, _| String::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoHostInUri(_));
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("super-secret"));
    }
}

#[test]
fn authenticated_uri_error_does_not_expose_domain_value() {
    let sensitive_domain = "username:super-secret@/value/path";
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domain", SecretJsonSelectorScope::Record)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let output = format!(r#"[{{"key":"token","value":"AAA","domain":"{sensitive_domain}"}}]"#);
    let error = compiled
        .rewrite(output.as_bytes(), &mut |_, _, _, _| String::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::InvalidUri { .. });
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains("super-secret"));
    }
}

#[test]
fn authenticated_uri_is_sanitized_and_credentials_are_stripped() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domain", SecretJsonSelectorScope::Record)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut domains = Vec::new();
    compiled
        .rewrite(
            br#"[{"key":"token","value":"AAA","domain":"http://username:password@example.com/path"}]"#, // trufflehog:ignore
            &mut |_, _, domain, _| {
                domains.push(domain.map(ToString::to_string));
                String::new()
            },
        )
        .unwrap();

    assert_eq!(domains, [Some("example.com".into())]);
}
