use firma_secret_provider::{CompiledMatcher, MatcherError, SecretPlaceholder};
use secrecy::ExposeSecret;

use crate::support::{json, json_record_key_name};

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
                pairs.push((name, value.expose_secret().to_owned()));
                SecretPlaceholder::new()
            },
        )
        .unwrap();
    let output = String::from_utf8(output).expect("valid utf8");

    insta::with_settings!({
        filters => vec![(r"fsp_[0-9a-z]{26}", "[placeholder]")],
    }, {
        insta::assert_snapshot!("relative_paths_rewrite_absolute_escaped_locations", output);
    });
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
            SecretPlaceholder::new()
        })
        .unwrap();
    let output = String::from_utf8(output).expect("valid utf8");

    insta::with_settings!({
        filters => vec![(r"fsp_[0-9a-z]{26}", "[placeholder]")],
    }, {
        insta::assert_snapshot!("root_relative_self_selection_rewrites_the_record", output);
    });
}

#[test]
fn record_key_name_is_derived_from_the_records_own_json_pointer() {
    let compiled = CompiledMatcher::compile(&json_record_key_name("$.data.data.*", "$")).unwrap();
    let mut pairs = Vec::new();
    let output = compiled
        .rewrite(
            br#"{"data":{"data":{"password":"hunter2","user":"admin"},"metadata":{"version":1}}}"#,
            &mut |name, value, _, _| {
                pairs.push((name, value.expose_secret().to_owned()));
                SecretPlaceholder::new()
            },
        )
        .unwrap();
    let output = String::from_utf8(output).expect("valid utf8");

    insta::with_settings!({
        filters => vec![(r"fsp_[0-9a-z]{26}", "[placeholder]")],
    }, {
        insta::assert_snapshot!("record_key_name_is_derived_from_the_records_own_json_pointer", output);
    });
    assert_eq!(
        pairs,
        [
            ("password".into(), "hunter2".into()),
            ("user".into(), "admin".into())
        ]
    );
}

#[test]
fn record_key_name_fails_closed_when_record_has_no_parent_key() {
    let compiled = CompiledMatcher::compile(&json_record_key_name("$", "$")).unwrap();
    let error = compiled
        .rewrite(br#""bare-secret""#, &mut |_, _, _, _| {
            SecretPlaceholder::new()
        })
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::RecordKeyUnavailable { record_index: 0 }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher name (record_key) has no parent key in record 0");
}

#[test]
fn zero_records_fails_closed() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();
    let error = compiled
        .rewrite(br"[]", &mut |_, _, _, _| SecretPlaceholder::new())
        .unwrap_err();

    std::assert_matches!(&error, MatcherError::NoRecords);
    insta::assert_snapshot!(error.to_string(), @"json matcher record_path selected no records");
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
                minted.push(name);
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::RecordSelectorMatchCount {
            selector: "value_path",
            record_index: 1,
            matches: 0
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher value_path selected 0 node(s) in record 1; expected exactly one");
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
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::RecordSelectorMatchCount {
            selector: "name",
            record_index: 1,
            matches: 2
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher name selected 2 node(s) in record 1; expected exactly one");
    assert_eq!(mint_count, 0);
}

#[test]
fn json_empty_matches_are_rejected() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(br#"[{"key":" ","value":"AAA"}]"#, &mut |name, _, _, _| {
            minted.push(name);
            SecretPlaceholder::new()
        })
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::EmptyNode {
            selector: "name",
            record_index: 0,
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher name selected a whitespace string in record 0");
    assert!(minted.is_empty());
}

#[test]
fn invalid_json_is_classified_with_its_location() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();
    let error = compiled
        .rewrite(br#"{"key":"value""#, &mut |_, _, _, _| {
            SecretPlaceholder::new()
        })
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::Json(source)
            if source.classify() == serde_json::error::Category::Eof
                && source.line() == 1
                && source.column() == 14
    );
}

#[test]
fn non_string_value_is_rejected() {
    let compiled = CompiledMatcher::compile(&json("$[*]", "$.value", "$.key")).unwrap();
    let error = compiled
        .rewrite(br#"[{"key":"token","value":42}]"#, &mut |_, _, _, _| {
            SecretPlaceholder::new()
        })
        .unwrap_err();

    std::assert_matches!(
        &error,
        MatcherError::NonStringNode {
            selector: "value_path",
            record_index: 0,
        }
    );
    insta::assert_snapshot!(error.to_string(), @"json matcher value_path selected a non-string node in record 0");
}
