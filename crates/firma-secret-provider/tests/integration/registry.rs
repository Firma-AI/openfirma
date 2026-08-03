use firma_core::{SecretMatcher, SecretNameSource};
use firma_secret_provider::{
    CompiledMatcher, IntegrationRegistry, MatcherRule, MatchingResolution, SecretPlaceholder,
    spec::cli::{ArgsAndMatcher, CliIntegrationSpec},
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
        MatchingResolution::Matcher(matcher) => matcher,
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
        MatchingResolution::Matcher(matcher) => matcher,
        other => panic!("expected a matcher, got {other:?}"),
    };
    assert!(matches!(
        list_matcher,
        SecretMatcher::Json { record_path, .. } if record_path == "$[*]"
    ));

    let get_matcher = match spec.resolve_args(&args(&["secret", "get", "some-id"])) {
        MatchingResolution::Matcher(matcher) => matcher,
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
        MatchingResolution::Matcher(_)
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
            MatchingResolution::PassThrough,
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
        ("doppler", &["secrets"][..]),
    ] {
        let _compiled =
            builtin_matcher(binary, command_args).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn documented_secret_paths_are_explicitly_blocked() {
    let registry = IntegrationRegistry::with_builtins();

    // Each of these is a real, documented retrieval path for its tool that
    // this registry has no matcher for (see the registry module docs), and
    // each now has its own `CliMatcherRule::BlockedCommand` rule rather than
    // relying on the implicit fail-closed fallback: none may be silently
    // forwarded unredacted.
    let cases: &[(&str, &[&str])] = &[
        ("bws", &["run", "--", "printenv"]),
        ("bws", &["secret", "create"]),
        ("bws", &["secret", "edit"]),
        ("bws", &["secret", "delete", "some-id"]),
        ("bws", &["project", "create", "backend"]),
        ("bws", &["project", "edit", "some-id"]),
        ("bws", &["project", "delete", "some-id"]),
        ("op", &["read", "op://vault/item/field"]),
        ("op", &["inject"]),
        ("op", &["document", "get", "some-id"]),
        ("op", &["document", "create", "file.pdf"]),
        ("vault", &["read", "secret/policy"]),
        (
            "vault",
            &["kv", "put", "secret/example", "password=hunter2"],
        ),
        (
            "vault",
            &["kv", "patch", "secret/example", "password=hunter2"],
        ),
        ("vault", &["kv", "delete", "secret/example"]),
        ("vault", &["kv", "destroy", "-versions=1", "secret/example"]),
        ("vault", &["kv", "rollback", "-version=1", "secret/example"]),
        (
            "vault",
            &["kv", "undelete", "-versions=1", "secret/example"],
        ),
        ("vault", &["kv", "metadata", "get", "secret/example"]),
        ("doppler", &["run", "--", "printenv"]),
        ("doppler", &["secrets", "get", "SOME_NAME", "--plain"]),
        (
            "doppler",
            &["secrets", "substitute", "template.tpl", "--output", "out"],
        ),
        ("doppler", &["secrets", "set", "SOME_NAME=value"]),
        ("doppler", &["secrets", "upload", "secrets.env"]),
        ("doppler", &["secrets", "delete", "SOME_NAME"]),
        ("doppler", &["secrets", "notes", "set", "SOME_NAME", "note"]),
    ];

    for (binary, case_args) in cases {
        let spec = registry
            .for_binary(binary)
            .unwrap_or_else(|| panic!("missing built-in spec for {binary}"));
        assert_eq!(
            spec.resolve_args(&args(case_args)),
            MatchingResolution::Blocked,
            "expected {binary} {case_args:?} to be blocked",
        );
    }
}

#[test]
fn unrecognized_invocation_falls_back_to_blocked() {
    let registry = IntegrationRegistry::with_builtins();

    // `vault login` matches no blocked, sensitive, or safe rule for `vault`
    // at all: it hits the implicit fail-closed fallback in
    // `CliIntegrationSpec::resolve_args`, distinct from an explicit
    // `BlockedCommand` rule.
    let spec = registry.for_binary("vault").expect("vault spec");
    assert_eq!(
        spec.resolve_args(&args(&["login"])),
        MatchingResolution::Blocked,
    );
}

#[test]
fn args_matches_tolerates_interspersed_flags() {
    let mut registry = IntegrationRegistry::with_builtins();
    registry.push(CliIntegrationSpec {
        binary_name: String::from("synthetic"),
        provider_id: String::from("test"),
        credential_env_vars: vec![],
        matchers: vec![MatcherRule::SensitiveCommand(ArgsAndMatcher {
            args_match: vec![String::from("get"), String::from("secret")],
            matcher: SecretMatcher::Json {
                record_path: String::from("$"),
                value_path: String::from("$.value"),
                name: SecretNameSource::Path {
                    path: String::from("$.key"),
                },
                item_selector: None,
                domain_selector: None,
            },
            strip_arg_flags: vec![],
            forced_args: vec![],
        })],
    });
    let spec = registry.for_binary("synthetic").expect("synthetic spec");

    // A leading global flag, and a `-f json`-style flag-value pair between
    // the matched tokens, must not break the match.
    let matches: &[&[&str]] = &[
        &["get", "secret"],
        &["--verbose", "get", "secret"],
        &["get", "-f", "json", "secret"],
    ];
    for case in matches {
        assert!(
            matches!(
                spec.resolve_args(&args(case)),
                MatchingResolution::Matcher(_)
            ),
            "expected {case:?} to match",
        );
    }

    // A positional token that is neither a flag nor the next expected
    // token is an unexpected argument, not a skippable flag value.
    let mismatches: &[&[&str]] = &[&["get", "other-secret"], &["list", "secret"]];
    for case in mismatches {
        assert_eq!(
            spec.resolve_args(&args(case)),
            MatchingResolution::Blocked,
            "expected {case:?} not to match",
        );
    }
}

#[test]
fn vault_global_flag_before_subcommand_is_tolerated() {
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.for_binary("vault").expect("vault spec");

    // Both the `-flag=value` and `-flag value` forms of a global flag placed
    // ahead of the subcommand must not defeat the `kv get` match.
    for case in [
        &["-namespace=team", "kv", "get", "secret/foo"][..],
        &["-namespace", "team", "kv", "get", "secret/foo"][..],
    ] {
        assert!(
            matches!(
                spec.resolve_args(&args(case)),
                MatchingResolution::Matcher(_)
            ),
            "expected {case:?} to match",
        );
    }
}

#[test]
fn unknown_binary_returns_none() {
    let registry = IntegrationRegistry::with_builtins();
    assert!(registry.for_binary("unknown-tool").is_none());
}

#[test]
fn bws_spec_has_expected_credential_env_and_provider_id() {
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
    registry.push(CliIntegrationSpec {
        binary_name: String::from("bws"),
        provider_id: String::from("custom"),
        credential_env_vars: vec![],
        matchers: vec![MatcherRule::SensitiveCommand(ArgsAndMatcher {
            args_match: vec![],
            matcher: SecretMatcher::Json {
                record_path: String::from("$[*]"),
                value_path: String::from("$.value"),
                name: SecretNameSource::Path {
                    path: String::from("$.key"),
                },
                item_selector: None,
                domain_selector: None,
            },
            strip_arg_flags: vec![],
            forced_args: vec![],
        })],
    });
    let spec = registry.for_binary("bws").expect("bws spec after push");
    assert!(spec.provider_id.eq("custom"));
    // The custom spec's empty args prefix matches every invocation in the
    // sensitive-command category.
    assert!(matches!(
        spec.resolve_args(&args(&["secret", "get"])),
        MatchingResolution::Matcher(_)
    ));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "data table, one entry per built-in rewrite case"
)]
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
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            "doppler",
            &["secrets", "download", "--format", "env"],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            "doppler",
            &["secrets", "download", "--format=env"],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            "doppler",
            // A positional file target must not survive the rewrite as
            // anything other than dead argv: `--no-file` is forced and,
            // per the CLI's own precedence, makes it inert.
            &["secrets", "download", "out.json"],
            &[
                "secrets",
                "download",
                "out.json",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            // `--fallback PATH` writes an encrypted copy of every secret to
            // an agent-chosen path regardless of `--no-file`; both it and
            // its value must be stripped rather than forwarded.
            "doppler",
            &["secrets", "download", "--fallback", "/tmp/exfil"],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            // An agent-supplied fallback passphrase would let it decrypt a
            // fallback file it can't otherwise write; must not survive.
            "doppler",
            &[
                "secrets",
                "download",
                "--fallback-passphrase",
                "hunter2", // trufflehog:ignore
            ],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            "doppler",
            &["secrets", "download", "--fallback-only"],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            "doppler",
            &["secrets", "download", "--fallback-readonly"],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        (
            // `--offline` is the CLI's own alias for `--fallback-only`.
            "doppler",
            &["secrets", "download", "--offline"],
            &[
                "secrets",
                "download",
                "--format",
                "json",
                "--no-file",
                "--no-fallback",
            ],
        ),
        ("doppler", &["secrets"], &["secrets", "--json"]),
        (
            // `--raw` adds a second, un-extracted secret-bearing field to
            // every record, so it must be stripped rather than forwarded.
            "doppler",
            &["secrets", "--raw"],
            &["secrets", "--json"],
        ),
        (
            // An agent-supplied `--json` (including an explicit `false`)
            // must not survive alongside the forced one.
            "doppler",
            &["secrets", "--json=false"],
            &["secrets", "--json"],
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
    registry.push(CliIntegrationSpec {
        binary_name: String::from("foo"),
        provider_id: String::from("test"),
        credential_env_vars: vec![],
        matchers: vec![MatcherRule::SensitiveCommand(ArgsAndMatcher {
            args_match: vec![],
            matcher: SecretMatcher::Json {
                record_path: String::from("$[*]"),
                value_path: String::from("$.value"),
                name: SecretNameSource::Path {
                    path: String::from("$.key"),
                },
                item_selector: None,
                domain_selector: None,
            },
            strip_arg_flags: vec![],
            forced_args: vec![],
        })],
    });
    let spec = registry.for_binary("foo").expect("foo spec");

    let rewritten = spec.rewrite_args(&args(&["secret", "get", "some-id"]));
    assert_eq!(rewritten, args(&["secret", "get", "some-id"]));
}

/// Builds a registry with a single custom `"foo"` spec whose lone
/// `SensitiveCommand` rule matches `args_match` and uses the given
/// `strip_arg_flags`/`forced_args`, for pinning
/// [`CliIntegrationSpec::rewrite_args`]'s flag-stripping behavior in
/// isolation from any built-in's other rules.
fn registry_with_strip_flags(
    args_match: Vec<String>,
    strip_arg_flags: Vec<String>,
    forced_args: Vec<String>,
) -> IntegrationRegistry {
    let mut registry = IntegrationRegistry::with_builtins();
    registry.push(CliIntegrationSpec {
        binary_name: String::from("foo"),
        provider_id: String::from("test"),
        credential_env_vars: vec![],
        matchers: vec![MatcherRule::SensitiveCommand(ArgsAndMatcher {
            args_match,
            matcher: SecretMatcher::Json {
                record_path: String::from("$[*]"),
                value_path: String::from("$.value"),
                name: SecretNameSource::Path {
                    path: String::from("$.key"),
                },
                item_selector: None,
                domain_selector: None,
            },
            strip_arg_flags,
            forced_args,
        })],
    });
    registry
}

#[test]
fn rewrite_args_does_not_swallow_a_flag_following_a_stripped_valueless_flag() {
    // Regression coverage for a bug where stripping a valueless (boolean)
    // flag unconditionally consumed whatever token followed it, even when
    // that token was itself another flag rather than a value — silently
    // deleting an unrelated flag instead of just the one being stripped.
    let cases: &[(&[&str], &[&str], &[&str])] = &[
        (
            // The flag right after the stripped boolean flag is not itself
            // stripped, so it and its own value must both survive intact.
            &["--bool-flag"],
            &["--bool-flag", "--other-flag", "value"],
            &["--other-flag", "value"],
        ),
        (
            // Two valueless flags back to back, both configured for
            // stripping, followed by a third flag that isn't: each of the
            // first two is removed independently on its own loop iteration
            // without swallowing the other, and the trailing flag survives.
            &["--bool-a", "--bool-b"],
            &["--bool-a", "--bool-b", "--other-flag"],
            &["--other-flag"],
        ),
        (
            // A stripped valueless flag as the very last token: there is no
            // following token to (incorrectly) consume.
            &["--bool-flag"],
            &["cmd", "--bool-flag"],
            &["cmd"],
        ),
        (
            // Contrast case: a flag that does take a value still has that
            // value correctly consumed, since the value doesn't look like a
            // flag itself. The fix must not regress this.
            &["--format"],
            &["--format", "json", "positional"],
            &["positional"],
        ),
    ];

    for (strip_arg_flags, requested, expected) in cases {
        let strip_arg_flags = strip_arg_flags.iter().map(|s| String::from(*s)).collect();
        let registry = registry_with_strip_flags(vec![], strip_arg_flags, vec![]);
        let spec = registry.for_binary("foo").expect("foo spec");
        assert_eq!(
            spec.rewrite_args(&args(requested)),
            args(expected),
            "unexpected rewritten args for {requested:?}",
        );
    }
}

#[test]
fn rewrite_args_does_not_swallow_an_args_match_token_following_a_stripped_valueless_flag() {
    // A stripped valueless flag immediately followed by one of the rule's
    // own `args_match` tokens must not swallow that token: it was already
    // relied on by `resolve_args` to select this very rule, so dropping it
    // from the rewritten args would execute a different, shorter command
    // than the one whose output shape the selected matcher expects.
    let registry = registry_with_strip_flags(
        vec![String::from("secrets"), String::from("download")],
        vec![String::from("--offline")],
        vec![String::from("--no-fallback")],
    );
    let spec = registry.for_binary("foo").expect("foo spec");

    let rewritten = spec.rewrite_args(&args(&["secrets", "--offline", "download"]));
    assert_eq!(rewritten, args(&["secrets", "download", "--no-fallback"]));
}

#[test]
fn doppler_secrets_download_rewrite_keeps_download_when_offline_precedes_it() {
    // Same scenario as above, against the real built-in doppler spec:
    // `args_matches` already tolerates a flag placed between `secrets` and
    // `download` (see `args_matches_tolerates_interspersed_flags`), so this
    // invocation resolves to the `secrets download` matcher. `rewrite_args`
    // must keep executing that same subcommand rather than silently
    // dropping `download` while stripping `--offline`.
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.for_binary("doppler").expect("doppler spec");

    let requested = args(&["secrets", "--offline", "download"]);
    assert!(matches!(
        spec.resolve_args(&requested),
        MatchingResolution::Matcher(_)
    ));
    let rewritten = spec.rewrite_args(&requested);
    assert_eq!(
        rewritten,
        args(&[
            "secrets",
            "download",
            "--format",
            "json",
            "--no-file",
            "--no-fallback",
        ]),
    );
}

#[test]
fn rewrite_args_does_not_strip_a_flag_value_that_looks_like_a_flag() {
    // Documents a known, intentional limitation shared with `args_matches`:
    // a stripped flag's value is only consumed when it doesn't start with
    // `-`. A value that itself looks like a flag (e.g. an agent-chosen
    // passphrase starting with `-`) survives the strip and is left in the
    // rewritten args as its own token, rather than being silently merged
    // into the removed flag.
    let registry =
        registry_with_strip_flags(vec![], vec![String::from("--fallback-passphrase")], vec![]);
    let spec = registry.for_binary("foo").expect("foo spec");

    let rewritten = spec.rewrite_args(&args(&["--fallback-passphrase", "-x", "positional"]));
    assert_eq!(rewritten, args(&["-x", "positional"]));
}

#[test]
fn rewrite_args_still_swallows_a_non_flag_token_after_a_stripped_valueless_flag() {
    // Documents a third known, intentional limitation: `strip_arg_flags`
    // carries no per-flag arity, just a flat list of names, so the stripping
    // loop cannot tell a genuinely valueless flag apart from one that takes
    // a value. A token immediately after a stripped flag is still treated
    // as that flag's value and removed whenever it's neither a flag itself
    // nor one of `args_match`'s own tokens — even if the stripped flag never
    // actually takes one. The fix only prevents swallowing a following flag
    // or `args_match` token; it does not, and cannot, restore per-flag
    // arity awareness for arbitrary positionals.
    let registry =
        registry_with_strip_flags(vec![], vec![String::from("--valueless-flag")], vec![]);
    let spec = registry.for_binary("foo").expect("foo spec");

    let rewritten = spec.rewrite_args(&args(&["--valueless-flag", "positional"]));
    assert_eq!(rewritten, args(&[]));
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
fn doppler_bare_secrets_matcher_is_distinct_from_download() {
    let registry = IntegrationRegistry::with_builtins();
    let spec = registry.for_binary("doppler").expect("doppler spec");

    // `secrets download` must keep resolving to its own flat-value matcher
    // rather than the bare `secrets` one below it in the rule list: a
    // shorter matcher (`["secrets"]`) is always contained in a longer one
    // that starts the same way, so this only holds because `resolve_args`
    // takes the *first* matching `SensitiveCommand` rule and `secrets
    // download` is listed first.
    let download_matcher = match spec.resolve_args(&args(&["secrets", "download"])) {
        MatchingResolution::Matcher(matcher) => matcher,
        other => panic!("expected a matcher, got {other:?}"),
    };
    assert!(matches!(
        download_matcher,
        SecretMatcher::Json { value_path, .. } if value_path == "$"
    ));

    let bare_matcher = match spec.resolve_args(&args(&["secrets"])) {
        MatchingResolution::Matcher(matcher) => matcher,
        other => panic!("expected a matcher, got {other:?}"),
    };
    assert!(matches!(
        bare_matcher,
        SecretMatcher::Json { value_path, .. } if value_path == "$.computed"
    ));
}

#[test]
fn doppler_bare_secrets_restricted_value_fails_closed() {
    let compiled =
        builtin_matcher("doppler", &["secrets"]).unwrap_or_else(|error| panic!("{error}"));
    let mut minted = Vec::new();
    let error = compiled
        .rewrite(
            br#"{"RESTRICTED_SECRET":{"computed":null,"note":"","computedVisibility":"masked","computedValueType":"secret"}}"#,
            &mut |name, _, _, _| {
                minted.push(name);
                SecretPlaceholder::new()
            },
        )
        .unwrap_err();

    std::assert_matches!(
        &error,
        firma_secret_provider::MatcherError::NonStringNode {
            selector: "value_path",
            record_index: 0,
        }
    );
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
    eprintln!("{compiled:?}");
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
    let doppler_multiline_secret =
        String::from("-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n"); // trufflehog:ignore
    let doppler_bare_db_secret = String::from("postgres://user:pass@host/bare-db"); // trufflehog:ignore
    let doppler_bare_api_secret = String::from("sk_live_bareSecretsCommand"); // trufflehog:ignore

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
            expected_entries: vec![
                Entry {
                    name: String::from("username"),
                    value: String::from("user.name"),
                    domains: vec![String::from("github.com")],
                    item: Some(String::from("GitHub")),
                },
                Entry {
                    name: String::from("token"),
                    value: op_secret,
                    domains: vec![String::from("github.com")],
                    item: Some(String::from("GitHub")),
                },
            ],
            unredacted: &[],
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
            name: "doppler_secrets_download_json",
            binary: "doppler",
            args: &["secrets", "download"],
            // `doppler secrets download --format json --no-file` output: a
            // flat object of NAME: value pairs. `TLS_PRIVATE_KEY` carries an
            // embedded newline (escaped, as JSON requires) to prove the JSON
            // matcher redacts multi-line values fully, unlike the old
            // line-anchored regex matcher this replaced.
            input: format!(
                r#"{{"DATABASE_URL":"postgres://user:pass@host/db","STRIPE_API_KEY":"{doppler_secret}","TLS_PRIVATE_KEY":"{}"}}"#, // trufflehog:ignore
                doppler_multiline_secret.replace('\n', "\\n")
            ),
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
                Entry {
                    name: String::from("TLS_PRIVATE_KEY"),
                    value: doppler_multiline_secret,
                    domains: vec![],
                    item: None,
                },
            ],
            unredacted: &[],
        },
        ProviderTestCase {
            name: "doppler_bare_secrets_json",
            binary: "doppler",
            args: &["secrets"],
            // `doppler secrets --json` output: each secret is a nested
            // object keyed by name, with the value under `computed`
            // alongside non-secret metadata (`note`, `computedVisibility`,
            // `computedValueType`) that must survive unredacted.
            input: format!(
                r#"{{"DATABASE_URL":{{"computed":"{doppler_bare_db_secret}","note":"prod db","computedVisibility":"unmasked","computedValueType":"string"}},"STRIPE_API_KEY":{{"computed":"{doppler_bare_api_secret}","note":"","computedVisibility":"masked","computedValueType":"string"}}}}"#
            ),
            expected_entries: vec![
                Entry {
                    name: String::from("DATABASE_URL"),
                    value: doppler_bare_db_secret,
                    domains: vec![],
                    item: None,
                },
                Entry {
                    name: String::from("STRIPE_API_KEY"),
                    value: doppler_bare_api_secret,
                    domains: vec![],
                    item: None,
                },
            ],
            unredacted: &["prod db", "unmasked", "masked"],
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
            MatchingResolution::Matcher(matcher) => matcher,
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
