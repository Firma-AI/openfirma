use firma_secret_provider::{CompiledMatcher, MatcherError};

use crate::support::{json, json_with_metadata, regex, selector};
use firma_core::SecretJsonSelectorScope;

#[test]
fn compile_rejects_bad_jsonpaths() {
    for matcher in [
        json("$[", "$.value", "$.key"),
        json("$", "$[", "$.key"),
        json("$", "$.value", "$["),
        json_with_metadata(
            "$",
            "$.value",
            "$.key",
            Some(selector("$[", SecretJsonSelectorScope::Record)),
            None,
        ),
    ] {
        let error = CompiledMatcher::compile(&matcher).unwrap_err();
        std::assert_matches!(
            error,
            MatcherError::JsonPath { path, .. } if path == "$["
        );
    }
}

#[test]
fn compile_rejects_invalid_regex() {
    let error = CompiledMatcher::compile(&regex("(")).unwrap_err();

    std::assert_matches!(error, MatcherError::Regex(regex::Error::Syntax(_)));
}

#[test]
fn compile_regex_requires_value_group() {
    let error = CompiledMatcher::compile(&regex("(?P<name>.+)")).unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::MissingGroup {
            missing: "value",
            found,
        } if found == "name"
    );
    insta::assert_snapshot!(error.to_string(), @"regex matcher must contain a named `value` capture group, found name");
}

#[test]
fn compile_regex_requires_name_group() {
    let error = CompiledMatcher::compile(&regex("(?P<value>.+)")).unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::MissingGroup {
            missing: "name",
            found,
        } if found == "value"
    );
    insta::assert_snapshot!(error.to_string(), @"regex matcher must contain a named `name` capture group, found value");
}
