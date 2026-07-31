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
        Some(selector("$.domain.host", SecretJsonSelectorScope::Record)),
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

    assert_eq!(metadata, [(None, vec![String::from("example.com")])]);
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
                let mut item_domains = matched.iter().map(ToString::to_string).collect::<Vec<_>>();
                item_domains.sort_unstable();
                domains.push(item_domains);
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
                let mut record_domains = matched.iter().map(ToString::to_string).collect::<Vec<_>>();
                record_domains.sort_unstable();
                domains.push(record_domains);
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
fn multiple_domains_are_normalized_without_losing_entries() {
    let matcher = json_with_metadata(
        "$",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domains[*]", SecretJsonSelectorScope::Document)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut domains = Vec::new();
    compiled
        .rewrite(
            br#"{"key":"token","value":"AAA","domains":["https://user:password@example.com/path?token=secret","api.example.com:8443","https://other.example/one","https://other.example/two"]}"#, // trufflehog:ignore
            &mut |_, _, matched, _| {
                domains.extend(matched.iter().map(ToString::to_string));
                SecretPlaceholder::new()
            },
        )
        .unwrap();
    domains.sort_unstable();

    assert_eq!(
        domains,
        ["api.example.com:8443", "example.com", "other.example",]
    );
}

#[test]
fn invalid_domain_among_multiple_matches_fails_before_minting() {
    let matcher = json_with_metadata(
        "$",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domains[*]", SecretJsonSelectorScope::Document)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            br#"{"key":"token","value":"AAA","domains":["example.com","/hostless"]}"#,
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
fn configured_domain_selector_rejects_zero_matches() {
    let matcher = json_with_metadata(
        "$",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domains[*]", SecretJsonSelectorScope::Document)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut minted = Vec::new();
    let result = compiled.rewrite(br#"{"key":"token","value":"AAA"}"#, &mut |name, _, _, _| {
        minted.push(name);
        SecretPlaceholder::new()
    });

    let Err(_error) = result else {
        panic!("a configured domain selector with no matches must fail closed");
    };
    assert!(minted.is_empty());
}

#[test]
fn configured_domain_selector_rejects_non_string_matches() {
    for domain in ["null", "42", "true", "{}", "[]"] {
        let matcher = json_with_metadata(
            "$",
            "$.value",
            "$.key",
            None,
            Some(selector("$.domain", SecretJsonSelectorScope::Document)),
        );
        let compiled = CompiledMatcher::compile(&matcher).unwrap();
        let input = format!(r#"{{"key":"token","value":"AAA","domain":{domain}}}"#);
        let mut minted = Vec::new();
        let result = compiled.rewrite(input.as_bytes(), &mut |name, _, _, _| {
            minted.push(name);
            SecretPlaceholder::new()
        });

        let Err(_error) = result else {
            panic!("non-string domain {domain} must fail closed");
        };
        assert!(minted.is_empty());
    }
}

#[test]
fn configured_domain_selector_rejects_mixed_validity() {
    let matcher = json_with_metadata(
        "$",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domains[*]", SecretJsonSelectorScope::Document)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut minted = Vec::new();
    let result = compiled.rewrite(
        br#"{"key":"token","value":"AAA","domains":["example.com",null]}"#,
        &mut |name, _, _, _| {
            minted.push(name);
            SecretPlaceholder::new()
        },
    );

    let Err(_error) = result else {
        panic!("a domain selector must reject mixed string and non-string matches");
    };
    assert!(minted.is_empty());
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
fn document_item_selector_rejects_multiple_matches() {
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
    insta::assert_snapshot!(error.to_string(), @"json matcher item_selector selected 2 document node(s); expected at most one");
}

#[test]
fn document_item_selector_accepts_zero_matches() {
    let matcher = json_with_metadata(
        "$.fields[*]",
        "$.value",
        "$.key",
        Some(selector("$.title", SecretJsonSelectorScope::Document)),
        None,
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let output = compiled.rewrite(
        br#"{"fields":[{"key":"a","value":"AAA"}]}"#,
        &mut |_, _, _, _| SecretPlaceholder::new(),
    );

    assert!(output.is_ok());
}

#[test]
fn document_domain_selector_rejects_zero_matches() {
    let matcher = json_with_metadata(
        "$.fields[*]",
        "$.value",
        "$.key",
        None,
        Some(selector("$.domain", SecretJsonSelectorScope::Document)),
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let error = compiled
        .rewrite(
            br#"{"fields":[{"key":"a","value":"AAA"}]}"#,
            &mut |_, _, _, _| SecretPlaceholder::new(),
        )
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoDomainMatched);
    insta::assert_snapshot!(error.to_string(), @"no domain matched");
}
