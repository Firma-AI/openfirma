use firma_core::SecretJsonSelectorScope;
use firma_secret_provider::{CompiledMatcher, MatcherError, SecretPlaceholder};

use crate::support::{json_with_metadata, selector};

#[test]
fn nested_record_metadata_is_evaluated_per_record() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.credentials.value",
        "$.credentials.key",
        Some(selector("$.metadata.item", SecretJsonSelectorScope::Record)),
        Some(selector(
            "$.metadata.domain",
            SecretJsonSelectorScope::Record,
        )),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut metadata = Vec::new();
    compiled
        .rewrite(
            br#"[{"credentials":{"key":"a","value":"AAA"},"metadata":{"item":"one","domain":"a.example"}},{"credentials":{"key":"b","value":"BBB"},"metadata":{"item":"two","domain":"b.example"}}]"#,
            &mut |name, _, domains, item| {
                metadata.push((
                    name,
                    item,
                    domains.iter().map(ToString::to_string).collect::<Vec<_>>(),
                ));
                SecretPlaceholder::new()
            },
        )
        .unwrap();

    assert_eq!(
        metadata,
        [
            ("a".into(), Some("one".into()), vec!["a.example".to_owned()]),
            ("b".into(), Some("two".into()), vec!["b.example".to_owned()])
        ]
    );
}

#[test]
fn document_scoped_one_password_metadata_broadcasts() {
    let matcher = json_with_metadata(
        "$.fields[*]",
        "$.value",
        "$.label",
        Some(selector("$.title", SecretJsonSelectorScope::Document)),
        Some(selector(
            "$.urls[0].href",
            SecretJsonSelectorScope::Document,
        )),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut metadata = Vec::new();
    compiled
        .rewrite(
            br#"{"title":"GitHub","fields":[{"label":"password","value":"AAA"},{"label":"token","value":"BBB"}],"urls":[{"href":"https://github.com/login"}]}"#,
            &mut |_, _, domains, item| {
                metadata.push((
                    item,
                    domains.iter().map(ToString::to_string).collect::<Vec<_>>(),
                ));
                SecretPlaceholder::new()
            },
        )
        .unwrap();

    assert_eq!(
        metadata,
        [
            (Some("GitHub".into()), vec!["github.com".to_owned()]),
            (Some("GitHub".into()), vec!["github.com".to_owned()])
        ]
    );
}

#[test]
fn record_scoped_singular_metadata_does_not_broadcast() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        Some(selector("$.title", SecretJsonSelectorScope::Record)),
        None,
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA","title":"one"},{"key":"b","value":"BBB"}]"#,
            &mut |name, _, _, _| {
                minted.push(name);
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::RecordSelectorMatchCount {
            selector: "item_selector",
            record_index: 1,
            matches: 0
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher item_selector selected 0 node(s) in record 1; expected exactly one");
    assert!(minted.is_empty());
}

#[test]
fn optional_non_string_metadata_remains_absent() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        Some(selector("$.item", SecretJsonSelectorScope::Record)),
        Some(selector("$.domain", SecretJsonSelectorScope::Record)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut metadata = Vec::new();
    compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA","item":null,"domain":{"host":"example.com"}}]"#,
            &mut |_, _, domains, item| {
                metadata.push((
                    item,
                    domains.iter().map(ToString::to_string).collect::<Vec<_>>(),
                ));
                SecretPlaceholder::new()
            },
        )
        .unwrap();

    assert_eq!(metadata, [(None, Vec::<String>::new())]);
}

#[test]
fn record_scoped_domain_selector_accepts_multiple_matches() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domains[*]", SecretJsonSelectorScope::Record)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut domains = Vec::new();
    compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA","domains":["a.example","b.example"]},{"key":"b","value":"BBB","domains":["c.example"]}]"#,
            &mut |_, _, matched, _| {
                domains.push(matched.iter().map(ToString::to_string).collect::<Vec<_>>());
                SecretPlaceholder::new()
            },
        )
        .unwrap();

    assert_eq!(
        domains,
        [
            vec!["a.example".to_owned(), "b.example".to_owned()],
            vec!["c.example".to_owned()]
        ]
    );
}

#[test]
fn document_scoped_domain_selector_accepts_multiple_matches_and_broadcasts() {
    let matcher = json_with_metadata(
        "$.fields[*]",
        "$.value",
        "$.key",
        None,
        Some(selector(
            "$.urls[*].href",
            SecretJsonSelectorScope::Document,
        )),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut domains = Vec::new();
    compiled
        .rewrite(
            br#"{"fields":[{"key":"a","value":"AAA"},{"key":"b","value":"BBB"}],"urls":[{"href":"https://a.example"},{"href":"https://b.example"}]}"#,
            &mut |_, _, matched, _| {
                domains.push(matched.iter().map(ToString::to_string).collect::<Vec<_>>());
                SecretPlaceholder::new()
            },
        )
        .unwrap();

    assert_eq!(
        domains,
        [
            vec!["a.example".to_owned(), "b.example".to_owned()],
            vec!["a.example".to_owned(), "b.example".to_owned()]
        ]
    );
}

#[test]
fn invalid_later_domain_fails_before_minting() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domain", SecretJsonSelectorScope::Record)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA","domain":"a.example"},{"key":"b","value":"BBB","domain":"/hostless"}]"#,
            &mut |name, _, _, _| {
                minted.push(name);
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoHostInUri(uri) if uri == "/hostless");
    insta::assert_snapshot!(error.to_string(), @"no host uri /hostless");
    assert!(minted.is_empty());
}

#[test]
fn document_selector_requires_exactly_one_match() {
    let matcher = json_with_metadata(
        "$.fields[*]",
        "$.value",
        "$.key",
        Some(selector("$.titles[*]", SecretJsonSelectorScope::Document)),
        None,
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();

    let error = compiled
        .rewrite(
            br#"{"fields":[{"key":"a","value":"AAA"}],"titles":["one","two"]}"#,
            &mut |_, _, _, _| SecretPlaceholder::new(),
        )
        .unwrap_err();
    std::assert_matches!(
        &error,
        MatcherError::DocumentSelectorMatchCount {
            selector: "item_selector",
            matches: 2
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher item_selector selected 2 document node(s); expected exactly one");
}

#[test]
fn document_selector_rejects_zero_matches() {
    let matcher = json_with_metadata(
        "$.fields[*]",
        "$.value",
        "$.key",
        Some(selector("$.title", SecretJsonSelectorScope::Document)),
        None,
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let error = compiled
        .rewrite(
            br#"{"fields":[{"key":"a","value":"AAA"}]}"#,
            &mut |_, _, _, _| SecretPlaceholder::new(),
        )
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::DocumentSelectorMatchCount {
            selector: "item_selector",
            matches: 0,
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher item_selector selected 0 document node(s); expected exactly one");
}
