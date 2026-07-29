use firma_secret_provider::{CompiledMatcher, MatcherError};

use crate::support::regex;

#[test]
fn regex_matcher_rewrites_value_spans() {
    let compiled =
        CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
    let output = compiled
        .rewrite(b"a=AAA\nb=BBB\n", &mut |name, _, _, _| format!("P:{name}"))
        .unwrap();
    assert_eq!(output, b"a=P:a\nb=P:b\n");
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
                minted.push(name.to_owned());
                String::new()
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
            minted.push(name.to_owned());
            String::new()
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
        .rewrite(&[0xff], &mut |_, _, _, _| String::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NotUtf8);
    insta::assert_snapshot!(error.to_string(), @"vault output is not valid UTF-8");
}

#[test]
fn regex_rejects_missing_runtime_value_capture() {
    let compiled =
        CompiledMatcher::compile(&regex(r"^(?P<name>[^=]+)(?:=(?P<value>.+))?$")).unwrap();
    let error = compiled
        .rewrite(b"token", &mut |_, _, _, _| String::new())
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
        .rewrite(b"not-a-pair", &mut |_, _, _, _| String::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoMatches);
    insta::assert_snapshot!(error.to_string(), @"no matches");
}
