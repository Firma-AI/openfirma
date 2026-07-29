use firma_secret_provider::{CompiledMatcher, MatcherError};

use crate::support::{json, json_with_metadata, regex, selector};
use firma_core::SecretJsonSelectorScope;

#[test]
fn compile_rejects_bad_jsonpath_and_regex() {
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
        std::assert_matches!(
            CompiledMatcher::compile(&matcher),
            Err(MatcherError::JsonPath { .. })
        );
    }
    std::assert_matches!(
        CompiledMatcher::compile(&regex("(")),
        Err(MatcherError::Regex(_))
    );
}

#[test]
fn compile_regex_requires_value_and_name_groups() {
    std::assert_matches!(
        CompiledMatcher::compile(&regex("(?P<name>.+)")),
        Err(MatcherError::MissingGroup {
            missing: "value",
            ..
        })
    );
    std::assert_matches!(
        CompiledMatcher::compile(&regex("(?P<value>.+)")),
        Err(MatcherError::MissingGroup {
            missing: "name",
            ..
        })
    );
}
