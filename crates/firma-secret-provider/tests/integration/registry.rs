use firma_core::{SecretMatcher, SecretNameSource};
use firma_secret_provider::{
    CliArgsResolution, CliIntegrationSpec, CliMatcherRule, CliSpecError, CompiledMatcher,
    IntegrationRegistry, SecretPlaceholder,
};

use crate::support::{Entry, rewrite_mint_placeholders};

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| String::from(*word)).collect()
}

fn builtin_matcher(binary: &str, command_args: &[&str]) -> Result<CompiledMatcher, String> {
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry
        .for_binary(binary)
        .ok_or_else(|| format!("missing built-in spec for {binary}"))?;
    let matcher = match spec.resolve_args(&args(command_args)) {
        CliArgsResolution::Matcher(matcher) => matcher,
        other => {
            return Err(format!(
                "expected matcher for {binary} {command_args:?}, got {other:?}"
            ));
        }
    };
    CompiledMatcher::compile(matcher)
        .map_err(|error| format!("failed to compile {binary} matcher: {error}"))
}

#[test]
fn builtins_cover_all_four_managers() {
    let registry = IntegrationRegistry::with_builtins();
    for name in ["bws", "op", "vault", "doppler"] {
        assert!(
            registry.for_binary(name).is_some(),
            "missing built-in spec for {name}"
        );
    }
}

#[test]
fn bws_matcher_resolves_by_subcommand() {
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.for_binary("bws").expect("bws spec");

    let list_matcher = match spec.resolve_args(&args(&["secret", "list"])) {
        CliArgsResolution::Matcher(matcher) => matcher,
        other => panic!("expected a matcher, got {other:?}"),
    };
    assert!(matches!(
        list_matcher,
        SecretMatcher::Json { record_path, .. } if record_path == "$[*]"
    ));

    let get_matcher = match spec.resolve_args(&args(&["secret", "get", "some-id"])) {
        CliArgsResolution::Matcher(matcher) => matcher,
        other => panic!("expected a matcher, got {other:?}"),
    };
    assert!(matches!(
        get_matcher,
        SecretMatcher::Json { record_path, .. } if record_path == "$"
    ));

    // Extra trailing args beyond the two-word prefix must not break the
    // prefix match.
    let get_matcher_with_trailing_args =
        spec.resolve_args(&args(&["secret", "get", "some-id", "--output", "json"]));
    assert!(matches!(
        get_matcher_with_trailing_args,
        CliArgsResolution::Matcher(_)
    ));
}

#[test]
fn all_builtin_known_safe_subcommands_pass_through() {
    let registry = IntegrationRegistry::with_builtins();
    let cases: &[(&str, &[&str])] = &[
        ("bws", &["project", "list"]),
        ("bws", &["project", "get", "some-id"]),
        ("op", &["whoami"]),
        ("op", &["account", "list"]),
        ("op", &["vault", "list"]),
        ("op", &["item", "list"]),
        ("vault", &["kv", "list", "secret/"]),
        ("vault", &["list", "secret/"]),
        ("vault", &["status"]),
        ("vault", &["policy", "list"]),
        ("doppler", &["me"]),
        ("doppler", &["projects", "list"]),
        ("doppler", &["environments", "list"]),
        ("doppler", &["configs", "list"]),
    ];

    for (binary, command_args) in cases {
        let spec = registry
            .for_binary(binary)
            .unwrap_or_else(|| panic!("missing built-in spec for {binary}"));
        assert_eq!(
            spec.resolve_args(&args(command_args)),
            CliArgsResolution::PassThrough,
            "expected {binary} {command_args:?} to pass through",
        );
    }
}

#[test]
fn all_builtin_secret_commands_select_a_compilable_matcher() {
    for (binary, command_args) in [
        ("bws", &["secret", "list"][..]),
        ("bws", &["secret", "get", "some-id"][..]),
        ("op", &["item", "get", "some-id"][..]),
        ("vault", &["kv", "get", "secret/example"][..]),
        ("doppler", &["secrets", "download"][..]),
    ] {
        let _compiled =
            builtin_matcher(binary, command_args).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn unrecognized_subcommands_are_blocked_fail_closed() {
    let registry = IntegrationRegistry::with_builtins();

    // Each of these is a real, documented retrieval path for its tool that
    // this registry has no matcher for (see the registry module docs): none
    // may be silently forwarded unredacted.
    let cases: &[(&str, &[&str])] = &[
        ("bws", &["run", "--", "printenv"]),
        ("bws", &["secret", "create"]),
        ("op", &["read", "op://vault/item/field"]),
        ("op", &["inject"]),
        ("vault", &["login"]),
        ("doppler", &["run", "--", "printenv"]),
        ("doppler", &["secrets", "get", "SOME_NAME", "--plain"]),
    ];

    for (binary, case_args) in cases {
        let spec = registry
            .for_binary(binary)
            .unwrap_or_else(|| panic!("missing built-in spec for {binary}"));
        assert_eq!(
            spec.resolve_args(&args(case_args)),
            CliArgsResolution::Blocked,
            "expected {binary} {case_args:?} to be blocked",
        );
    }
}

#[test]
fn unknown_binary_returns_none() {
    let registry = IntegrationRegistry::with_builtins();
    assert!(registry.for_binary("unknown-tool").is_none());
}

#[test]
fn bws_spec_has_expected_credential_env_and_placeholder() {
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.for_binary("bws").expect("bws spec");
    assert!(
        spec.credential_env_vars
            .iter()
            .any(|v| v == "BWS_ACCESS_TOKEN")
    );
    assert!(spec.provider_id.eq("bitwarden"));
}

#[test]
fn push_custom_spec_takes_precedence_over_builtin() {
    let mut registry = IntegrationRegistry::with_builtins();
    registry
        .push(CliIntegrationSpec {
            binary_name: String::from("bws"),
            provider_id: String::from("custom"),
            credential_env_vars: vec![],
            matchers: vec![CliMatcherRule {
                args_match: None,
                matcher: Some(SecretMatcher::Json {
                    record_path: String::from("$[*]"),
                    value_path: String::from("$.value"),
                    name: SecretNameSource::Path {
                        path: String::from("$.key"),
                    },
                    item_selector: None,
                    domain_selector: None,
                }),
            }],
            strip_arg_flags: vec![],
            forced_args: vec![],
        })
        .expect("valid custom spec");
    let spec = registry.for_binary("bws").expect("bws spec after push");
    assert!(spec.provider_id.eq("custom"));
    // The custom spec's args_match: None makes it a universal fallback,
    // overriding both of the built-in's subcommand-specific rules.
    assert!(matches!(
        spec.resolve_args(&args(&["secret", "get"])),
        CliArgsResolution::Matcher(_)
    ));
}

#[test]
fn all_builtin_specs_validate() {
    let registry = IntegrationRegistry::with_builtins();
    for name in ["bws", "op", "vault", "doppler"] {
        let spec = registry
            .for_binary(name)
            .unwrap_or_else(|| panic!("missing built-in spec for {name}"));
        assert!(
            spec.validate().is_ok(),
            "built-in {name} failed to validate"
        );
    }
}

#[test]
fn validate_rejects_a_fallback_rule_that_is_also_a_pass_through() {
    let spec = CliIntegrationSpec {
        binary_name: String::from("footgun"),
        provider_id: String::from("footgun"),
        credential_env_vars: vec![],
        // args_match: None (fallback) + matcher: None (pass-through) means
        // every invocation this spec doesn't otherwise recognize is
        // forwarded unredacted instead of blocked — the opposite of fail
        // closed.
        matchers: vec![CliMatcherRule {
            args_match: None,
            matcher: None,
        }],
        strip_arg_flags: vec![],
        forced_args: vec![],
    };

    assert_eq!(
        spec.validate(),
        Err(CliSpecError::AmbiguousFallbackPassThrough {
            binary_name: String::from("footgun"),
        })
    );
}

#[test]
fn push_rejects_ambiguous_fallback_pass_through_and_leaves_registry_unchanged() {
    let mut registry = IntegrationRegistry::with_builtins();

    let result = registry.push(CliIntegrationSpec {
        binary_name: String::from("bws"),
        provider_id: String::from("malicious-replacement"),
        credential_env_vars: vec![],
        matchers: vec![CliMatcherRule {
            args_match: None,
            matcher: None,
        }],
        strip_arg_flags: vec![],
        forced_args: vec![],
    });

    assert_eq!(
        result,
        Err(CliSpecError::AmbiguousFallbackPassThrough {
            binary_name: String::from("bws"),
        })
    );
    // The built-in must still be in place: a rejected push must not
    // partially apply.
    let spec = registry.for_binary("bws").expect("bws spec");
    assert!(spec.provider_id.eq("bitwarden"));
}

#[test]
fn a_pass_through_scoped_to_a_specific_prefix_is_not_ambiguous() {
    // Unlike the args_match: None + matcher: None combo, a pass-through
    // scoped to a specific prefix only forwards that one invocation shape
    // unredacted; it doesn't weaken the spec's fail-closed default for
    // everything else, so it must validate cleanly.
    let spec = CliIntegrationSpec {
        binary_name: String::from("footgun"),
        provider_id: String::from("footgun"),
        credential_env_vars: vec![],
        matchers: vec![CliMatcherRule {
            args_match: Some(vec![String::from("whoami")]),
            matcher: None,
        }],
        strip_arg_flags: vec![],
        forced_args: vec![],
    };

    assert_eq!(spec.validate(), Ok(()));
}

#[test]
fn builtins_force_expected_output_formats() {
    let registry = IntegrationRegistry::with_builtins();
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "bws",
            &["secret", "get", "id"],
            &["secret", "get", "id", "--output", "json"],
        ),
        (
            "bws",
            &["secret", "get", "id", "--output", "table"],
            &["secret", "get", "id", "--output", "json"],
        ),
        (
            "bws",
            &["secret", "get", "id", "--output=yaml"],
            &["secret", "get", "id", "--output", "json"],
        ),
        (
            "op",
            &["item", "get", "id"],
            &["item", "get", "id", "--format", "json"],
        ),
        (
            "op",
            &["item", "get", "id", "--format", "table"],
            &["item", "get", "id", "--format", "json"],
        ),
        (
            "op",
            &["item", "get", "id", "--format=table"],
            &["item", "get", "id", "--format", "json"],
        ),
        (
            "vault",
            &["kv", "get", "secret/foo"],
            &["kv", "get", "secret/foo", "-format", "json"],
        ),
        (
            "vault",
            &["kv", "get", "-format", "table", "secret/foo"],
            &["kv", "get", "secret/foo", "-format", "json"],
        ),
        (
            "vault",
            &["kv", "get", "-format=table", "secret/foo"],
            &["kv", "get", "secret/foo", "-format", "json"],
        ),
        (
            "vault",
            &["kv", "get", "--format", "table", "secret/foo"],
            &["kv", "get", "secret/foo", "-format", "json"],
        ),
        (
            "doppler",
            &["secrets", "download"],
            &["secrets", "download", "--format", "env"],
        ),
        (
            "doppler",
            &["secrets", "download", "--format", "json"],
            &["secrets", "download", "--format", "env"],
        ),
        (
            "doppler",
            &["secrets", "download", "--format=json"],
            &["secrets", "download", "--format", "env"],
        ),
    ];

    for (binary, requested, expected) in cases {
        let spec = registry
            .for_binary(binary)
            .unwrap_or_else(|| panic!("missing built-in spec for {binary}"));
        assert_eq!(
            spec.rewrite_args(&args(requested)),
            args(expected),
            "unexpected rewritten args for {binary} {requested:?}",
        );
    }
}

#[test]
fn rewrite_args_leaves_args_untouched_when_no_strip_flags_configured() {
    let mut registry = IntegrationRegistry::with_builtins();
    registry
        .push(CliIntegrationSpec {
            binary_name: String::from("foo"),
            provider_id: String::from("test"),
            credential_env_vars: vec![],
            matchers: vec![CliMatcherRule {
                args_match: None,
                matcher: Some(SecretMatcher::Json {
                    record_path: String::from("$[*]"),
                    value_path: String::from("$.value"),
                    name: SecretNameSource::Path {
                        path: String::from("$.key"),
                    },
                    item_selector: None,
                    domain_selector: None,
                }),
            }],
            strip_arg_flags: vec![],
            forced_args: vec![],
        })
        .expect("insert successful");
    let spec = registry.for_binary("foo").expect("foo spec");

    let rewritten = spec.rewrite_args(&args(&["secret", "get", "some-id"]));
    assert_eq!(rewritten, args(&["secret", "get", "some-id"]));
}

#[test]
fn vault_kv_v1_output_fails_closed() {
    let compiled = builtin_matcher("vault", &["kv", "get", "secret/example"])
        .unwrap_or_else(|error| panic!("{error}"));
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            br#"{"data":{"password":"hunter2"}}"#,
            &mut |name, _, _, _| {
                minted.push(name);
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(&error, firma_secret_provider::MatcherError::NoRecords);
    insta::assert_snapshot!(error.to_string(), @"json matcher record_path selected no records");
    assert!(minted.is_empty());
}

#[test]
fn vault_field_output_fails_closed() {
    let compiled = builtin_matcher("vault", &["kv", "get", "-field=password", "secret/example"])
        .unwrap_or_else(|error| panic!("{error}"));
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(b"hunter2\n", &mut |name, _, _, _| {
            minted.push(name);
            SecretPlaceholder::new()
        })
        .unwrap_err();

    std::assert_matches!(&error, firma_secret_provider::MatcherError::Json(_));
    assert!(minted.is_empty());
}

#[test]
fn op_redacts_secrets_in_custom_string_fields() {
    let compiled = builtin_matcher("op", &["item", "get", "example"])
        .unwrap_or_else(|error| panic!("{error}"));
    let input = br#"{
        "title":"Production",
        "urls":[{"href":"https://api.example.com"}],
        "fields":[
            {"id":"password","type":"CONCEALED","label":"password","value":"password-secret"},
            {"id":"custom-api-key","type":"STRING","label":"api key","value":"string-secret"}
        ]
    }"#;
    let (output, entries) = rewrite_mint_placeholders(&compiled, input)
        .unwrap_or_else(|error| panic!("1Password rewrite failed: {error}"));

    assert_eq!(
        entries,
        [
            Entry {
                name: String::from("password"),
                value: String::from("password-secret"),
                domains: vec![String::from("api.example.com")],
                item: Some(String::from("Production")),
            },
            Entry {
                name: String::from("api key"),
                value: String::from("string-secret"),
                domains: vec![String::from("api.example.com")],
                item: Some(String::from("Production")),
            },
        ]
    );
    assert!(
        !output
            .windows(b"string-secret".len())
            .any(|window| window == b"string-secret")
    );
}

#[test]
fn op_rewrites_multiple_secret_fields() {
    let compiled = builtin_matcher("op", &["item", "get", "example"])
        .unwrap_or_else(|error| panic!("{error}"));
    let input = br#"{
        "title":"Production",
        "urls":[{"href":"https://api.example.com"}],
        "fields":[
            {"id":"password","type":"CONCEALED","label":"password","value":"first-secret"},
            {"id":"api-key","type":"CONCEALED","label":"api key","value":"second-secret"}
        ]
    }"#;
    let (output, entries) = rewrite_mint_placeholders(&compiled, input)
        .unwrap_or_else(|error| panic!("1Password rewrite failed: {error}"));

    assert_eq!(entries.len(), 2);
    for secret in [b"first-secret".as_slice(), b"second-secret".as_slice()] {
        assert!(!output.windows(secret.len()).any(|window| window == secret));
    }
}

#[test]
fn op_redacts_password_and_leaves_totp_clear() {
    let compiled = builtin_matcher("op", &["item", "get", "example"])
        .unwrap_or_else(|error| panic!("{error}"));
    let input = br#"{
        "title":"Production",
        "urls":[{"href":"https://login.example.com"}],
        "fields":[
            {"id":"password","type":"CONCEALED","label":"password","value":"password-secret"},
            {"id":"otp","type":"OTP","label":"one-time password","value":"123456"}
        ]
    }"#;
    let (output, entries) = rewrite_mint_placeholders(&compiled, input)
        .unwrap_or_else(|error| panic!("1Password rewrite failed: {error}"));

    assert_eq!(
        entries,
        [Entry {
            name: String::from("password"),
            value: String::from("password-secret"),
            domains: vec![String::from("login.example.com")],
            item: Some(String::from("Production")),
        }]
    );
    assert!(output.windows(6).any(|window| window == b"123456"));
    assert!(
        !output
            .windows(15)
            .any(|window| window == b"password-secret")
    );
}

/// One built-in provider output fixture: which spec + CLI invocation
/// produced `input`, what extraction is expected to yield, and (for cases
/// exercising fail-closed exclusions) substrings that must survive the
/// rewrite verbatim because they are not secret material.
struct ProviderTestCase {
    name: &'static str,
    binary: &'static str,
    args: &'static [&'static str],
    input: String,
    expected_entries: Vec<Entry>,
    unredacted: &'static [&'static str],
}

#[expect(
    clippy::too_many_lines,
    reason = "data table, one entry per built-in fixture"
)]
fn provider_test_cases() -> Vec<ProviderTestCase> {
    let op_secret = String::from("ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ12"); // trufflehog:ignore
    let op_future_secret = String::from("passkey-blob-should-still-be-redacted");
    let bws_list_secret = String::from("s3cr3t-db-p4ssw0rd"); // trufflehog:ignore
    let bws_get_secret = String::from("sk_live_51H8x-redacted"); // trufflehog:ignore
    let vault_secret = String::from("hunter2"); // trufflehog:ignore
    let doppler_secret = String::from("sk_live_51H8xdopplersecret"); // trufflehog:ignore

    vec![
        ProviderTestCase {
            name: "op_secret_field_with_item_and_domain",
            binary: "op",
            args: &[
                "item",
                "get",
                "abcd1234efgh5678ijkl9012mnop3456",
                "--format",
                "json",
            ],
            input: format!(
                r#"{{
              "id": "abcd1234efgh5678ijkl9012mnop3456",
              "title": "GitHub",
              "vault": {{
                "id": "qrstuv1234567890wxyz",
                "name": "Employee"
              }},
              "category": "LOGIN",
              "urls": [
                {{
                  "primary": true,
                  "href": "https://github.com/login"
                }}
              ],
              "fields": [
                {{
                  "id": "username",
                  "type": "STRING",
                  "label": "username",
                  "value": "user.name"
                }},
                {{
                  "id": "password",
                  "type": "CONCEALED",
                  "label": "token",
                  "value": "{op_secret}"
                }}
              ]
            }}"#
            ),
            expected_entries: vec![Entry {
                name: String::from("token"),
                value: op_secret,
                domains: vec![String::from("github.com")],
                item: Some(String::from("GitHub")),
            }],
            unredacted: &["user.name"],
        },
        ProviderTestCase {
            name: "op_excludes_only_known_non_secret_field_types",
            binary: "op",
            args: &["item", "get", "abcd1234efgh5678ijkl9012mnop3456"],
            input: format!(
                r#"{{
              "id": "abcd1234efgh5678ijkl9012mnop3456",
              "title": "GitHub",
              "vault": {{
                "id": "qrstuv1234567890wxyz",
                "name": "Employee"
              }},
              "category": "LOGIN",
              "urls": [
                {{
                  "primary": true,
                  "href": "https://github.com/login"
                }}
              ],
              "fields": [
                {{
                  "id": "cc-type",
                  "type": "CREDIT_CARD_TYPE",
                  "label": "card brand",
                  "value": "Visa"
                }},
                {{
                  "id": "future-field",
                  "type": "PASSKEY",
                  "label": "passkey",
                  "value": "{op_future_secret}"
                }}
              ]
            }}"#
            ),
            expected_entries: vec![Entry {
                name: String::from("passkey"),
                value: op_future_secret,
                domains: vec![String::from("github.com")],
                item: Some(String::from("GitHub")),
            }],
            // Known non-secret field type CREDIT_CARD_TYPE must not be
            // redacted; an unrecognized type (PASSKEY) fails closed instead.
            unredacted: &["Visa"],
        },
        ProviderTestCase {
            name: "bws_secret_list",
            binary: "bws",
            args: &["secret", "list"],
            input: format!(
                r#"[
              {{
                "id": "5f0f4e6e-8c8b-4f9c-9f2f-b1a900f3c3d2",
                "organizationId": "b8a9c1e2-3d4f-4a5b-8c6d-7e8f9a0b1c2d",
                "projectId": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
                "key": "DATABASE_URL",
                "value": "{bws_list_secret}",
                "note": "",
                "creationDate": "2026-01-15T10:22:31.000Z",
                "revisionDate": "2026-06-01T09:14:02.000Z"
              }}
            ]"#
            ),
            expected_entries: vec![Entry {
                name: String::from("DATABASE_URL"),
                value: bws_list_secret,
                domains: vec![],
                item: None,
            }],
            unredacted: &[],
        },
        ProviderTestCase {
            name: "bws_secret_get",
            binary: "bws",
            args: &["secret", "get", "5f0f4e6e-8c8b-4f9c-9f2f-b1a900f3c3d2"],
            input: format!(
                r#"{{
              "id": "5f0f4e6e-8c8b-4f9c-9f2f-b1a900f3c3d2",
              "organizationId": "b8a9c1e2-3d4f-4a5b-8c6d-7e8f9a0b1c2d",
              "projectId": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
              "key": "STRIPE_API_KEY",
              "value": "{bws_get_secret}",
              "note": "",
              "creationDate": "2026-02-03T14:05:11.000Z",
              "revisionDate": "2026-02-03T14:05:11.000Z"
            }}"#
            ),
            expected_entries: vec![Entry {
                name: String::from("STRIPE_API_KEY"),
                value: bws_get_secret,
                domains: vec![],
                item: None,
            }],
            unredacted: &[],
        },
        ProviderTestCase {
            name: "vault_kv_v2_get",
            binary: "vault",
            args: &["kv", "get", "secret/myapp"],
            // `vault kv get -format=json` on a KV v2 mount: the secret's
            // name is the `data.data` object's own key, with no separate
            // name/label field anywhere in the document.
            input: format!(
                r#"{{
              "request_id": "abcd1234-5678-90ab-cdef-1234567890ab",
              "data": {{
                "data": {{
                  "password": "{vault_secret}",
                  "username": "alice"
                }},
                "metadata": {{
                  "version": 1
                }}
              }}
            }}"#
            ),
            expected_entries: vec![
                Entry {
                    name: String::from("password"),
                    value: vault_secret,
                    domains: vec![],
                    item: None,
                },
                Entry {
                    name: String::from("username"),
                    value: String::from("alice"),
                    domains: vec![],
                    item: None,
                },
            ],
            unredacted: &[],
        },
        ProviderTestCase {
            name: "doppler_secrets_download_env",
            binary: "doppler",
            args: &["secrets", "download", "--format", "env"],
            input: format!(
                "DATABASE_URL=postgres://user:pass@host/db\nSTRIPE_API_KEY={doppler_secret}\n" // trufflehog:ignore
            ), // trufflehog:ignore
            expected_entries: vec![
                Entry {
                    name: String::from("DATABASE_URL"),
                    value: String::from("postgres://user:pass@host/db"),
                    domains: vec![],
                    item: None,
                },
                Entry {
                    name: String::from("STRIPE_API_KEY"),
                    value: doppler_secret,
                    domains: vec![],
                    item: None,
                },
            ],
            unredacted: &[],
        },
    ]
}

#[test]
fn builtin_provider_outputs_are_captured_and_redacted() {
    for case in provider_test_cases() {
        let registry = IntegrationRegistry::with_builtins();
        let spec = registry.for_binary(case.binary).unwrap_or_else(|| {
            panic!(
                "case {}: missing built-in spec for {}",
                case.name, case.binary
            )
        });
        let matcher_args = args(case.args);
        let secret_matcher = match spec.resolve_args(&matcher_args) {
            CliArgsResolution::Matcher(matcher) => matcher,
            other => panic!(
                "case {}: expected a matcher for {} {:?}, got {other:?}",
                case.name, case.binary, case.args
            ),
        };
        let compiled = CompiledMatcher::compile(secret_matcher)
            .unwrap_or_else(|err| panic!("case {}: spec fails to compile: {err}", case.name));

        let (out, entries) = rewrite_mint_placeholders(&compiled, case.input.as_bytes())
            .unwrap_or_else(|err| panic!("case {}: rewrite failed: {err}", case.name));
        let out = String::from_utf8(out).unwrap_or_else(|err| {
            panic!("case {}: rewritten output is not utf8: {err}", case.name)
        });

        assert_eq!(entries, case.expected_entries, "case {}", case.name);

        for entry in &case.expected_entries {
            assert!(
                !out.contains(entry.value.as_str()),
                "case {}: secret value for {:?} leaked into rewritten output:\n{out}",
                case.name,
                entry.name
            );
        }
        for substring in case.unredacted {
            assert!(
                out.contains(substring),
                "case {}: expected {substring:?} to survive the rewrite unredacted:\n{out}",
                case.name
            );
        }

        insta::with_settings!({
            filters => vec![(r"fsp_[0-9a-z]{26}", "[placeholder]")],
        }, {
            insta::assert_snapshot!(case.name, out);
        });
    }
}
