use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher};
use firma_secret_provider::{CompiledMatcher, MatcherError};
use serde_json::Value;

fn selector(path: &str, scope: SecretJsonSelectorScope) -> SecretJsonSelector {
    SecretJsonSelector {
        path: path.to_owned(),
        scope,
    }
}

fn json(record_path: &str, value_path: &str, name_path: &str) -> SecretMatcher {
    SecretMatcher::Json {
        record_path: record_path.to_owned(),
        value_path: value_path.to_owned(),
        name_path: name_path.to_owned(),
        item_selector: None,
        domain_selector: None,
    }
}

fn json_with_metadata(
    record_path: &str,
    value_path: &str,
    name_path: &str,
    item_selector: Option<SecretJsonSelector>,
    domain_selector: Option<SecretJsonSelector>,
) -> SecretMatcher {
    SecretMatcher::Json {
        record_path: record_path.to_owned(),
        value_path: value_path.to_owned(),
        name_path: name_path.to_owned(),
        item_selector,
        domain_selector,
    }
}

fn regex(pattern: &str) -> SecretMatcher {
    SecretMatcher::Regex {
        pattern: pattern.to_owned(),
    }
}

#[test]
fn scoped_selector_serde_shape_is_explicit() {
    let matcher = json_with_metadata(
        "$[*]",
        "$.credentials.value",
        "$.credentials.key",
        Some(selector(
            "$.metadata.title",
            SecretJsonSelectorScope::Record,
        )),
        Some(selector("$.domain", SecretJsonSelectorScope::Document)),
    );

    let serialized = serde_json::to_value(matcher).unwrap();

    assert_eq!(
        serialized,
        serde_json::json!({
            "type": "json",
            "record_path": "$[*]",
            "value_path": "$.credentials.value",
            "name_path": "$.credentials.key",
            "item_selector": {"path": "$.metadata.title", "scope": "record"},
            "domain_selector": {"path": "$.domain", "scope": "document"}
        })
    );
}

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
fn relative_paths_rewrite_absolute_escaped_locations() {
    let matcher = json(
        "$.groups['a/b~c'][*]",
        "$.credentials['v/~']",
        "$.credentials.key",
    );
    let compiled = CompiledMatcher::compile(&matcher).unwrap();
    let mut pairs = Vec::new();
    let output = compiled
        .rewrite(
            br#"{"groups":{"a/b~c":[{"credentials":{"key":"first","v/~":"AAA"}},{"credentials":{"key":"second","v/~":"BBB"}}]},"credentials":{"v/~":"ROOT"}}"#,
            &mut |name, value, _, _| {
                pairs.push((name.to_owned(), value.expose().to_owned()));
                format!("P:{name}")
            },
        )
        .unwrap();
    let output: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(
        output["groups"]["a/b~c"][0]["credentials"]["v/~"],
        "P:first"
    );
    assert_eq!(
        output["groups"]["a/b~c"][1]["credentials"]["v/~"],
        "P:second"
    );
    assert_eq!(output["credentials"]["v/~"], "ROOT");
    assert_eq!(
        pairs,
        [
            ("first".into(), "AAA".into()),
            ("second".into(), "BBB".into())
        ]
    );
}

#[test]
fn root_relative_self_selection_rewrites_the_record() {
    let compiled = CompiledMatcher::compile(&json("$.token", "$", "$")).unwrap();
    let output = compiled
        .rewrite(br#"{"token":"AAA","other":"AAA"}"#, &mut |_, _, _, _| {
            "PLACEHOLDER".to_owned()
        })
        .unwrap();
    let output: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(
        output,
        serde_json::json!({"token": "PLACEHOLDER", "other": "AAA"})
    );
}

#[test]
fn zero_records_fails_closed() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();

    std::assert_matches!(
        compiled.rewrite(br"[]", &mut |_, _, _, _| String::new()),
        Err(MatcherError::NoRecords)
    );
}

#[test]
fn missing_record_value_fails_before_minting() {
    let compiled =
        CompiledMatcher::compile(&json("$[*]", "$.credentials.value", "$.credentials.key"))
            .unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            br#"[{"credentials":{"key":"a","value":"AAA"}},{"credentials":{"key":"b"}}]"#,
            &mut |name, _, _, _| {
                minted.push(name.to_owned());
                String::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(
        error,
        MatcherError::RecordSelectorMatchCount {
            selector: "value_path",
            record_index: 1,
            matches: 0
        }
    );
    assert!(minted.is_empty());
}

#[test]
fn multiple_record_name_matches_fail_before_minting() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$..name")).unwrap();
    let mut mint_count = 0;
    let error = compiled
        .rewrite(
            br#"[{"value":"AAA","name":"a"},{"value":"BBB","name":"b","nested":{"name":"other"}}]"#,
            &mut |_, _, _, _| {
                mint_count += 1;
                String::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(
        error,
        MatcherError::RecordSelectorMatchCount {
            selector: "name_path",
            record_index: 1,
            matches: 2
        }
    );
    assert_eq!(mint_count, 0);
}

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
        error,
        MatcherError::RecordSelectorMatchCount {
            selector: "item_selector",
            record_index: 1,
            matches: 0
        }
    );
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

    std::assert_matches!(error, MatcherError::NoHostInUri(_));
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
        error,
        MatcherError::DocumentSelectorMatchCount {
            selector: "item_selector",
            matches: 2
        }
    );
}

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

    std::assert_matches!(error, MatcherError::NoDomainMatched);
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

    std::assert_matches!(
        error,
        MatcherError::EmptyGroup(missing) if missing == "name"
    );
    assert!(minted.is_empty());
}

#[test]
fn json_empty_matches_are_rejected() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(br#"[{"key":" ","value":"AAA"}]"#, &mut |name, _, _, _| {
            minted.push(name.to_owned());
            String::new()
        })
        .unwrap_err();

    std::assert_matches!(
        error,
        MatcherError::EmptyNode { selector, .. } if selector == "name_path"
    );
    assert!(minted.is_empty());
}

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
