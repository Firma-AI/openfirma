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
