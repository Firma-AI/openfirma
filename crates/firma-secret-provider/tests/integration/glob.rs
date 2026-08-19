use firma_secret_provider::glob_match;

#[test]
fn glob_exact_match() {
    assert!(glob_match("api.example.com", "api.example.com"));
    assert!(!glob_match("api.example.com", "api.other.com"));
}

#[test]
fn glob_empty_pattern_matches_only_empty_value() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "anything"));
}

#[test]
fn glob_star_matches_empty_sequence() {
    assert!(glob_match("a*b", "ab"));
    assert!(glob_match("a*b", "aXYb"));
}

#[test]
fn glob_leading_and_trailing_wildcards() {
    assert!(glob_match("*a", "xxa"));
    assert!(glob_match("a*", "axx"));
    assert!(glob_match("*a*", "xxayy"));
    assert!(!glob_match("*a*", "xxb"));
}

#[test]
fn glob_multiple_wildcards() {
    assert!(glob_match("a*b*c", "aXbYc"));
    assert!(!glob_match("a*b*c", "aXbY"));
    assert!(glob_match("a**b", "ab"));
    assert!(glob_match("a**b", "aXXb"));
}

#[test]
fn glob_wildcard_does_not_take_anchoring_from_first_part_when_absent() {
    // A leading `*` must not require the first literal to match at the
    // start of the value.
    assert!(glob_match("*.example.com", "api.example.com"));
    assert!(glob_match("*.example.com", "deep.api.example.com"));
}

#[test]
fn glob_is_case_sensitive() {
    assert!(!glob_match("api.example.com", "API.Example.com"));
}
