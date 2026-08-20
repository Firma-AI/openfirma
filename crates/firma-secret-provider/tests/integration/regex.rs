use firma_secret_provider::{CompiledMatcher, MatcherError, SecretPlaceholder};

use crate::support::regex;

#[test]
fn regex_matcher_rewrites_value_spans() {
    let compiled =
        CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
    let output = compiled
        .rewrite(b"a=AAA\nb=BBB\n", &mut |_, _, _, _| {
            SecretPlaceholder::new()
        })
        .unwrap();
    let output = String::from_utf8(output).expect("valid utf8");

    insta::with_settings!({
        filters => vec![(r"fsp_[0-9a-z]{26}", "[placeholder]")],
    }, {
        insta::assert_snapshot!("regex_matcher_rewrites_value_spans", output);
    });
}

#[test]
fn regex_missing_domain_is_rejected_atomically() {
    let compiled = CompiledMatcher::compile(&regex(
        r"(?m)^(?P<name>[^=]+)=(?P<value>[^@\n]+)(?:@(?P<domain>\S+))?$",
    ))
    .unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            b"first=AAA@first.example\nsecond=BBB\n",
            &mut |name, _, _, _| {
                minted.push(name);
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoDomainMatched);
    insta::assert_snapshot!(error.to_string(), @"no domain matched");
    assert!(minted.is_empty());
}

#[test]
fn regex_empty_matches_are_rejected() {
    let compiled = CompiledMatcher::compile(&regex(
        r"(?m)^(?P<name>[^=]*)=(?P<value>[^@\n]*)(?:@(?P<domain>\S*))?$",
    ))
    .unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(b" =AAA@first.example", &mut |name, _, _, _| {
            minted.push(name);
            SecretPlaceholder::new()
        })
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::EmptyGroup("name"));
    insta::assert_snapshot!(error.to_string(), @"regex matches an empty capture group: `name`");
    assert!(minted.is_empty());
}

#[test]
fn regex_rejects_invalid_utf8() {
    let compiled = CompiledMatcher::compile(&regex(r"(?P<name>[^=]+)=(?P<value>.+)")).unwrap();
    let error = compiled
        .rewrite(&[0xff], &mut |_, _, _, _| SecretPlaceholder::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NotUtf8);
    insta::assert_snapshot!(error.to_string(), @"vault output is not valid UTF-8");
}

#[test]
fn regex_rejects_missing_runtime_value_capture() {
    let compiled =
        CompiledMatcher::compile(&regex(r"^(?P<name>[^=]+)(?:=(?P<value>.+))?$")).unwrap();
    let error = compiled
        .rewrite(b"token", &mut |_, _, _, _| SecretPlaceholder::new())
        .unwrap_err();

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
fn regex_rejects_output_without_matches() {
    let compiled = CompiledMatcher::compile(&regex(r"(?P<name>[^=]+)=(?P<value>.+)")).unwrap();
    let error = compiled
        .rewrite(b"not-a-pair", &mut |_, _, _, _| SecretPlaceholder::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoMatches);
    insta::assert_snapshot!(error.to_string(), @"no matches");
}

#[test]
fn regex_rejects_missing_runtime_name_capture() {
    // The alternation lets `value` participate while `name` stays absent.
    let compiled = CompiledMatcher::compile(&regex(r"^(?:x(?P<name>a)|(?P<value>b))$")).unwrap();
    let error = compiled
        .rewrite(b"b", &mut |_, _, _, _| SecretPlaceholder::new())
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::MissingGroup {
            missing: "name",
            found,
        } if found == "value"
    );
    insta::assert_snapshot!(error.to_string(), @"regex matcher must contain a named `name` capture group, found value");
}
