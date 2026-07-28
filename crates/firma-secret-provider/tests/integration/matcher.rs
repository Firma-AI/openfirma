use firma_core::SecretMatcher;
use firma_secret_provider::{CompiledMatcher, MatcherError};
use serde_json::Value;

fn json(value_path: &str, name_path: &str) -> SecretMatcher {
    SecretMatcher::Json {
        value_path: value_path.to_string(),
        name_path: name_path.to_string(),
        item_path: None,
        domain_path: None,
    }
}

fn json_with_item(
    value_path: &str,
    name_path: &str,
    item_path: &str,
    domain_path: Option<&str>,
) -> SecretMatcher {
    SecretMatcher::Json {
        value_path: value_path.to_string(),
        name_path: name_path.to_string(),
        item_path: Some(item_path.to_string()),
        domain_path: domain_path.map(str::to_owned),
    }
}

fn json_with_domain(value_path: &str, name_path: &str, domain_path: &str) -> SecretMatcher {
    SecretMatcher::Json {
        value_path: value_path.to_string(),
        name_path: name_path.to_string(),
        item_path: None,
        domain_path: Some(domain_path.to_string()),
    }
}

fn json_with_url_domain(value_path: &str, name_path: &str, domain_path: &str) -> SecretMatcher {
    SecretMatcher::Json {
        value_path: value_path.to_string(),
        name_path: name_path.to_string(),
        item_path: None,
        domain_path: Some(domain_path.to_string()),
    }
}

fn regex(pattern: &str) -> SecretMatcher {
    SecretMatcher::Regex {
        pattern: pattern.to_string(),
    }
}

#[test]
fn compile_rejects_bad_jsonpath_and_regex() {
    assert!(matches!(
        CompiledMatcher::compile(&json("$[", "$.key")),
        Err(MatcherError::JsonPath { .. })
    ));
    assert!(matches!(
        CompiledMatcher::compile(&regex("(")),
        Err(MatcherError::Regex(_))
    ));
}

#[test]
fn compile_regex_requires_value_and_name_groups() {
    std::assert_matches!(
        CompiledMatcher::compile(&regex("(?P<name>.+)")),
        Err(MatcherError::MissingGroup { missing, .. }) if missing == "value"
    );
    std::assert_matches!(
        CompiledMatcher::compile(&regex("(?P<value>.+)")),
        Err(MatcherError::MissingGroup { missing, .. }) if missing == "name"
    );
    assert!(CompiledMatcher::compile(&regex("(?P<name>[^=]+)=(?P<value>.+)")).is_ok());
}

#[test]
fn json_matcher_rewrites_values_and_reports_pairs() {
    let compiled = CompiledMatcher::compile(&json("$[*].value", "$[*].key")).unwrap();
    let mut pairs = Vec::new();
    let out = compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA"},{"key":"b","value":"BBB"}]"#,
            &mut |name, value, _domain, _item| {
                pairs.push((name.to_string(), value.expose().to_string()));
                format!("P:{name}")
            },
        )
        .unwrap();
    let out: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out[0]["value"], serde_json::json!("P:a"));
    assert_eq!(out[1]["value"], serde_json::json!("P:b"));
    assert_eq!(
        pairs,
        vec![
            ("a".to_string(), "AAA".to_string()),
            ("b".to_string(), "BBB".to_string())
        ]
    );
}

#[test]
fn json_matcher_rejects_misaligned_paths_and_bad_json() {
    let compiled = CompiledMatcher::compile(&json("$[*].value", "$[*].missing")).unwrap();
    assert!(matches!(
        compiled.rewrite(br#"[{"key":"a","value":"AAA"}]"#, &mut |_, _, _, _| {
            String::new()
        }),
        Err(MatcherError::Misaligned {
            values: 1,
            names: 0
        })
    ));

    let compiled = CompiledMatcher::compile(&json("$.value", "$.key")).unwrap();
    assert!(matches!(
        compiled.rewrite(b"not json", &mut |_, _, _, _| String::new()),
        Err(MatcherError::Json(_))
    ));
}

#[test]
fn json_name_path_rejects_equal_counts_from_different_parents() {
    let compiled =
        CompiledMatcher::compile(&json("$[?(@.value)].value", "$[?(@.key)].key")).unwrap();
    let mut names_minted = Vec::new();
    let result = compiled.rewrite(
        br#"[{"value":"AAA"},{"key":"b","value":"BBB"},{"key":"c"}]"#,
        &mut |name, _, _, _| {
            names_minted.push(name.to_owned());
            String::new()
        },
    );

    std::assert_matches!(result, Err(MatcherError::NameParentMismatch));
    assert!(names_minted.is_empty());
}

#[test]
fn regex_matcher_rewrites_value_spans() {
    let compiled =
        CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
    let out = compiled
        .rewrite(b"a=AAA\nb=BBB\n", &mut |name, _, _, _| format!("P:{name}"))
        .unwrap();
    assert_eq!(out, b"a=P:a\nb=P:b\n");
}

#[test]
fn regex_matcher_rejects_non_utf8() {
    let compiled = CompiledMatcher::compile(&regex(r"(?P<name>.)=(?P<value>.)")).unwrap();
    assert!(matches!(
        compiled.rewrite(&[0xff, 0xfe], &mut |_, _, _, _| String::new()),
        Err(MatcherError::NotUtf8)
    ));
}

#[test]
fn regex_domain_group_passes_domain_to_mint() {
    let compiled = CompiledMatcher::compile(&regex(
        r"(?m)^(?P<name>[^=]+)=(?P<value>[^@]+)@(?P<domain>.+)$",
    ))
    .unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    let out = compiled
        .rewrite(
            b"token=ghp_abc@api.github.com\n",
            &mut |_, _, domain, _item| {
                domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
                "PLACEHOLDER".to_string()
            },
        )
        .unwrap();
    assert_eq!(out, b"token=PLACEHOLDER@api.github.com\n");
    assert_eq!(domains_seen, vec![Some("api.github.com".to_owned())]);
}

#[test]
fn regex_domain_is_url_extracts_host() {
    let spec = SecretMatcher::Regex {
        pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>[^ ]+) (?P<domain>\S+)$".to_string(),
    };
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    compiled
        .rewrite(
            b"token=ghp_abc https://github.com/login\n",
            &mut |_, _, domain, _item| {
                domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
                "PLACEHOLDER".to_string()
            },
        )
        .unwrap();
    assert_eq!(domains_seen, vec![Some("github.com".to_owned())]);
}

#[test]
fn regex_missing_domain_is_rejected() {
    let spec = SecretMatcher::Regex {
        pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>[^ ]+)((?P<domain>\S+)|)$".to_string(),
    };
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    let res = compiled.rewrite(b"token=ghp_abc\n", &mut |_, _, domain, _item| {
        domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
        "PLACEHOLDER".to_string()
    });
    assert!(domains_seen.is_empty());
    std::assert_matches!(res, Err(MatcherError::NoDomainMatched));
}

#[test]
fn regex_without_domain_group_passes_none() {
    let compiled =
        CompiledMatcher::compile(&regex(r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$")).unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    compiled
        .rewrite(b"token=ghp_abc\n", &mut |_, _, domain, _item| {
            domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
            "PLACEHOLDER".to_string()
        })
        .unwrap();
    assert_eq!(domains_seen, vec![None]);
}

#[test]
fn regex_validation_does_not_mint_before_all_matches_are_valid() {
    let spec = SecretMatcher::Regex {
        pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>[^@\n]+)(?:@(?P<domain>\S+))?$".to_string(),
    };
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut names_minted = Vec::new();
    let result = compiled.rewrite(
        b"first=AAA@first.example\nsecond=BBB\n",
        &mut |name, _, _, _| {
            names_minted.push(name.to_owned());
            "PLACEHOLDER".to_string()
        },
    );

    std::assert_matches!(result, Err(MatcherError::NoDomainMatched));
    assert_eq!(names_minted, Vec::<String>::new());
}

#[test]
fn json_domain_path_passes_domain_to_mint() {
    let spec = json_with_domain("$[*].value", "$[*].key", "$[*].domain");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    compiled
            .rewrite(
                br#"[{"key":"a","value":"AAA","domain":"api.github.com"},{"key":"b","value":"BBB","domain":null}]"#,
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
                    String::new()
                },
            )
            .unwrap();
    assert_eq!(domains_seen, vec![Some("api.github.com".to_owned()), None]);
}

#[test]
fn json_domain_path_broadcasts_single_node_to_all_values() {
    // Simulates 1Password: $.urls[0].href is a single URL for the whole
    // item, but there are N sensitive fields. The single domain is broadcast
    // to all extracted values.
    let spec = json_with_domain("$.fields[*].value", "$.fields[*].label", "$.urls[0].href");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    compiled
            .rewrite(
                br#"{"fields":[{"label":"password","value":"s3cr3t"},{"label":"token","value":"ghp_x"}],"urls":[{"href":"github.com"}]}"#,
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
                    String::new()
                },
            )
            .unwrap();
    // 1 domain selected → broadcast to both values
    assert_eq!(
        domains_seen,
        vec![Some("github.com".to_owned()), Some("github.com".to_owned())]
    );
}

#[test]
fn json_domain_is_url_extracts_host() {
    let spec = json_with_url_domain("$.fields[*].value", "$.fields[*].label", "$.urls[0].href");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    compiled
            .rewrite(
                br#"{"fields":[{"label":"password","value":"s3cr3t"},{"label":"token","value":"ghp_x"}],"urls":[{"href":"https://github.com/login"}]}"#,
                &mut |_, _, domain, _item| {
                    domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
                    String::new()
                },
            )
            .unwrap();
    // URL "https://github.com/login" → host "github.com", broadcast to both
    assert_eq!(
        domains_seen,
        vec![Some("github.com".to_owned()), Some("github.com".to_owned())]
    );
}

#[test]
fn json_domain_path_rejects_misaligned_count() {
    // 3 values, 2 domain nodes (one item lacks the field) → error.
    // Note: 0 domains means wildcard (not an error); the error fires only
    // when M domains are selected where M != 0, 1, or value_count.
    let spec = json_with_domain("$[*].value", "$[*].key", "$[*].domain");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    assert!(matches!(
            compiled.rewrite(
                br#"[{"key":"a","value":"AAA","domain":"a.com"},{"key":"b","value":"BBB","domain":"b.com"},{"key":"c","value":"CCC"}]"#,
                &mut |_, _, _, _| String::new()
            ),
            Err(MatcherError::DomainMisaligned {
                values: 3,
                domains: 2
            })
        ));
}

#[test]
fn json_positional_domain_path_rejects_one_missing_domain() {
    let spec = json_with_domain("$[*].value", "$[*].key", "$[*].domain");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut names_minted = Vec::new();
    let result = compiled.rewrite(
        br#"[{"key":"a","value":"AAA","domain":"a.example"},{"key":"b","value":"BBB"}]"#,
        &mut |name, _, _, _| {
            names_minted.push(name.to_owned());
            String::new()
        },
    );

    std::assert_matches!(
        result,
        Err(MatcherError::DomainMisaligned {
            values: 2,
            domains: 1
        })
    );
    assert_eq!(names_minted, Vec::<String>::new());
}

#[test]
fn json_item_path_broadcasts_title_to_all_fields() {
    // Simulates 1Password: $.title is one string for the whole item, but
    // there are N sensitive fields. The item title is broadcast to all.
    let spec = json_with_item("$.fields[*].value", "$.fields[*].label", "$.title", None);
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut items_seen: Vec<Option<String>> = Vec::new();
    compiled
            .rewrite(
                br#"{"title":"GitHub","fields":[{"label":"password","value":"s3cr3t"},{"label":"token","value":"ghp_x"}]}"#,
                &mut |_, _, _, item| {
                    items_seen.push(item.map(str::to_owned));
                    String::new()
                },
            )
            .unwrap();
    assert_eq!(
        items_seen,
        vec![Some("GitHub".to_owned()), Some("GitHub".to_owned())]
    );
}

#[test]
fn json_positional_metadata_requires_sibling_nodes() {
    let spec = json_with_item("$[*].value", "$[*].key", "$[*].item", Some("$[*].domain"));
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut metadata = Vec::new();
    compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA","item":"one","domain":"a.example"},{"key":"b","value":"BBB","item":"two","domain":"b.example"}]"#,
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
        vec![
            (
                "a".to_owned(),
                Some("one".to_owned()),
                Some("a.example".to_owned())
            ),
            (
                "b".to_owned(),
                Some("two".to_owned()),
                Some("b.example".to_owned())
            )
        ]
    );
}

#[test]
fn json_item_path_rejects_equal_counts_from_different_parents() {
    let spec = json_with_item(
        "$[?(@.value)].value",
        "$[?(@.value)].key",
        "$[?(@.item)].item",
        None,
    );
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut names_minted = Vec::new();
    let result = compiled.rewrite(
        br#"[{"key":"a","value":"AAA"},{"key":"b","value":"BBB","item":"two"},{"item":"three"}]"#,
        &mut |name, _, _, _| {
            names_minted.push(name.to_owned());
            String::new()
        },
    );

    std::assert_matches!(result, Err(MatcherError::ItemParentMismatch));
    assert!(names_minted.is_empty());
}

#[test]
fn json_positional_paths_reject_nested_non_sibling_nodes() {
    let spec = json_with_domain(
        "$[*].credentials.value",
        "$[*].credentials.key",
        "$[*].metadata.domain",
    );
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut names_minted = Vec::new();
    let result = compiled.rewrite(
        br#"[{"credentials":{"key":"a","value":"AAA"},"metadata":{"domain":"a.example"}}]"#,
        &mut |name, _, _, _| {
            names_minted.push(name.to_owned());
            String::new()
        },
    );

    std::assert_matches!(result, Err(MatcherError::DomainParentMismatch));
    assert!(names_minted.is_empty());
}

#[test]
fn json_paths_reject_equal_counts_from_different_parents() {
    let spec = json_with_domain(
        "$[?(@.value)].value",
        "$[?(@.value)].key",
        "$[?(@.domain)].domain",
    );
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let mut names_minted = Vec::new();
    let result = compiled.rewrite(
        br#"[{"key":"a","value":"AAA"},{"key":"b","value":"BBB","domain":"b.example"},{"domain":"c.example"}]"#,
        &mut |name, _, _, _| {
            names_minted.push(name.to_owned());
            String::new()
        },
    );
    std::assert_matches!(result, Err(MatcherError::DomainParentMismatch));
    assert!(names_minted.is_empty());
}

#[test]
fn secret_doesnt_leak_contents() {
    let compiled = CompiledMatcher::compile(&json("$[*].value", "$[*].key")).unwrap();
    let mut secrets = Vec::new();
    let _out = compiled
        .rewrite(
            br#"[{"key":"a","value":"AAA"},{"key":"b","value":"BBB"}]"#,
            &mut |_name, value, _domain, _item| {
                secrets.push(value.to_string());
                String::new()
            },
        )
        .unwrap();
    assert_eq!(
        secrets,
        vec!["<secret>".to_string(), "<secret>".to_string()]
    );
}

#[test]
fn hostless_uri_error_does_not_expose_domain_value() {
    let sensitive_domain = "/vault/path?token=super-secret";
    let spec = json_with_url_domain("$[*].value", "$[*].key", "$[*].domain");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let output = format!(r#"[{{"key":"token","value":"AAA","domain":"{sensitive_domain}"}}]"#);
    let error = compiled
        .rewrite(output.as_bytes(), &mut |_, _, _, _| String::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoHostInUri(_));
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendered.contains("super-secret"),
            "URI error exposed the domain value: {rendered}"
        );
    }
}

#[test]
fn authenticated_uri_error_does_not_expose_domain_value() {
    let sensitive_domain = "username:super-secret@/value/path";
    let spec = json_with_url_domain("$[*].value", "$[*].key", "$[*].domain");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let output = format!(r#"[{{"key":"token","value":"AAA","domain":"{sensitive_domain}"}}]"#);
    let error = compiled
        .rewrite(output.as_bytes(), &mut |_, _, _, _| String::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::InvalidUri { .. });
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendered.contains("super-secret"),
            "URI error exposed the domain value: {rendered}"
        );
    }
}

#[test]
fn authority_with_credentials_gets_stripped() {
    let sensitive_domain = "http://username:password@example.com/path/to/resource"; // trufflehog:ignore
    let spec = json_with_url_domain("$[*].value", "$[*].key", "$[*].domain");
    let compiled = CompiledMatcher::compile(&spec).unwrap();
    let output = format!(r#"[{{"key":"token","value":"AAA","domain":"{sensitive_domain}"}}]"#);
    let mut domains_seen: Vec<Option<String>> = Vec::new();
    compiled
        .rewrite(output.as_bytes(), &mut |_, _, domain, _| {
            domains_seen.push(domain.map(|domain| domain.as_str().to_owned()));
            String::new()
        })
        .unwrap();

    assert_eq!(domains_seen.len(), 1);
    let domain = domains_seen.pop().unwrap();
    assert_eq!(domain, Some("example.com".to_owned()));
}
