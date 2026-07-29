use firma_core::SecretJsonSelectorScope;
use firma_secret_provider::{CompiledMatcher, MatcherError};

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
            &mut |name, _, domain, item| {
                metadata.push((
                    name.to_owned(),
                    item.map(str::to_owned),
                    domain.map(ToString::to_string),
                ));
                String::new()
            },
        )
        .unwrap();

    assert_eq!(
        metadata,
        [
            ("a".into(), Some("one".into()), Some("a.example".into())),
            ("b".into(), Some("two".into()), Some("b.example".into()))
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
            &mut |_, _, domain, item| {
                metadata.push((item.map(str::to_owned), domain.map(ToString::to_string)));
                String::new()
            },
        )
        .unwrap();

    assert_eq!(
        metadata,
        [
            (Some("GitHub".into()), Some("github.com".into())),
            (Some("GitHub".into()), Some("github.com".into()))
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
                minted.push(name.to_owned());
                String::new()
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
            &mut |_, _, domain, item| {
                metadata.push((item.map(str::to_owned), domain.map(ToString::to_string)));
                String::new()
            },
        )
        .unwrap();

    assert_eq!(metadata, [(None, None)]);
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
                minted.push(name.to_owned());
                String::new()
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
            &mut |_, _, _, _| String::new(),
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
            &mut |_, _, _, _| String::new(),
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
