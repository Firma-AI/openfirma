//! Built-in integration specs for supported CLI secret managers.
//!
//! Each spec names the vault CLI binary, lists the credential env vars the
//! broker must forward to the subprocess, and specifies how to classify
//! commands and extract secrets from the tool's stdout. Placeholder minting is
//! owned by the caller of the extraction engine.
//!
//! CLI-only: every built-in is a vault CLI tool. There are no built-in HTTP
//! vaults — every HTTP provider must be fully user-defined (matching how
//! custom CLI integrations already work).
//!
//! The registry is keyed by binary basename; a launcher whose basename is not in
//! the registry can still be permitted or passed through by Cedar, but no
//! intercept transform is applied (the output is forwarded unchanged).
//!
//! ## Fail-closed subcommand resolution
//!
//! Each built-in spec lists rules for the invocation shapes it recognizes.
//! A [`CliMatcherRule::SensitiveCommand`] is a known secret-emitting shape
//! (extract and redact); a [`CliMatcherRule::SafeCommand`] is a known-safe
//! pass-through (e.g. a `list` subcommand that only ever returns names/ids,
//! never secret values); a [`CliMatcherRule::BlockedCommand`] is a known
//! secret-emitting shape this registry has no way to extract or redact from
//! (e.g. a subcommand that injects secrets as env vars for a child process,
//! or prints a bare secret value with no structure a matcher can anchor on)
//! and is therefore forbidden outright rather than forwarded unredacted. Per
//! [`CliIntegrationSpec::resolve_args`](crate::CliIntegrationSpec::resolve_args),
//! blocked commands are checked first, then sensitive, then safe; an
//! invocation whose args match none of the three is also
//! [`CliArgsResolution::Blocked`](crate::CliArgsResolution::Blocked) — fail
//! closed by default, on the assumption that an unrecognized invocation
//! shape may emit secret material this registry has no way to extract or
//! redact. See each built-in's function-level doc comment below for the
//! specific retrieval paths explicitly blocked or implicitly closed off for
//! that tool, and for the remaining gaps that `args_match` alone can't close
//! (a subcommand whose *shape* is recognized but whose output doesn't fit
//! the matcher, e.g. `vault kv get` against a KV v1 mount).

use std::collections::BTreeMap;

use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher, SecretNameSource};

use crate::{
    non_empty::vec::non_empty_vec,
    spec::{
        MatcherRule,
        cli::{ArgsAndMatcher, ArgsOnly, CliIntegrationSpec},
    },
};

/// Registry of CLI integration specs, keyed by binary basename.
///
/// Starts with the four built-in specs and can be extended with custom specs
/// loaded from `firma.toml` (`secret_providers` table entries). Custom specs
/// take precedence over built-ins when names collide.
#[derive(Debug, Default)]
pub struct IntegrationRegistry {
    specs: BTreeMap<String, CliIntegrationSpec>,
}

impl IntegrationRegistry {
    /// Build a registry containing the built-in specs for all supported vault
    /// CLIs.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self {
            specs: [bws_spec(), op_spec(), vault_spec(), doppler_spec()]
                .into_iter()
                .map(|spec| (spec.binary_name.clone(), spec))
                .collect(),
        }
    }

    /// Look up a spec by binary basename. Returns `None` for unknown tools.
    #[must_use]
    pub fn for_binary(&self, binary_name: &str) -> Option<&CliIntegrationSpec> {
        self.specs.get(binary_name)
    }

    /// Add a custom spec. If a spec with the same binary name already exists
    /// (e.g. a built-in), the custom one replaces it.
    pub fn push(&mut self, spec: CliIntegrationSpec) {
        if let Some(old_spec) = self.specs.insert(spec.binary_name.clone(), spec) {
            tracing::warn!("replacing {} secret manager specs", old_spec.binary_name);
        }
    }
}

// `bws secret list` returns a JSON array of secret records; `bws secret get
// <id>` returns a single record, unwrapped. Same binary, same flat record
// shape, but the matcher's record_path depends on which subcommand was
// invoked.
//
// `project list`/`project get` return only project id/name/organizationId —
// no secret material — so they pass through unredacted rather than needing a
// matcher.
//
// `bws run -- <command>` injects secrets as env vars for a child process and
// never prints them; `bws secret create`/`edit` echo the secret value back.
// All three are explicitly blocked below rather than left to the implicit
// fail-closed default, since they are real, documented retrieval paths.
fn bws_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("bws"),
        provider_id: String::from("bitwarden"),
        credential_env_vars: vec![String::from("BWS_ACCESS_TOKEN")],
        matchers: vec![
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("run")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secret"), String::from("create")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secret"), String::from("edit")],
            }),
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("secret"), String::from("list")],
                matcher: SecretMatcher::Json {
                    record_path: String::from("$[*]"),
                    value_path: String::from("$.value"),
                    name: SecretNameSource::Path {
                        path: String::from("$.key"),
                    },
                    item_selector: None,
                    domain_selector: None,
                },
            }),
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("secret"), String::from("get")],
                matcher: SecretMatcher::Json {
                    record_path: String::from("$"),
                    value_path: String::from("$.value"),
                    name: SecretNameSource::Path {
                        path: String::from("$.key"),
                    },
                    item_selector: None,
                    domain_selector: None,
                },
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("get")],
            }),
        ],
        strip_arg_flags: vec![String::from("--output")],
        forced_args: vec![String::from("--output"), String::from("json")],
    }
}

// `op item get <item> --format json` returns a single item object. Field types
// 1Password documents as non-secret metadata (ADDRESS, CREDIT_CARD_TYPE, DATE,
// EMAIL, GENDER, MENU, MONTH_YEAR, PHONE, REFERENCE, URL) are left unchanged.
// OTP is also left unchanged so the numeric one-time code remains usable.
// STRING fields are redacted because custom text fields may hold sensitive
// material such as recovery codes. Fail closed: an unrecognized `type` —
// including any field type 1Password adds after this list was written — falls
// through the exclusion and is treated as a secret and redacted, even if it
// turns out not to need it. Every item URL is normalized, deduplicated, and
// broadcast as a domain scope for all extracted fields.
//
// `whoami`/`account list`/`vault list`/`item list` return account, vault, or
// item metadata (ids, titles, categories) with no field values, so they pass
// through unredacted rather than needing a matcher.
//
// `op read op://vault/item/field` and `op inject` print the raw secret as
// plain text, not JSON. Both are explicitly blocked below rather than left
// to the implicit fail-closed default, since they are real, documented
// retrieval paths.
fn op_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("op"),
        provider_id: String::from("1password"),
        credential_env_vars: vec![String::from("OP_SERVICE_ACCOUNT_TOKEN")],
        matchers: vec![
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("read")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("inject")],
            }),
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("item"), String::from("get")],
                matcher: SecretMatcher::Json {
                    record_path: String::from(concat!(
                        "$.fields[?(",
                        "@.type != \"ADDRESS\"",
                        " && @.type != \"CREDIT_CARD_TYPE\"",
                        " && @.type != \"DATE\"",
                        " && @.type != \"EMAIL\"",
                        " && @.type != \"GENDER\"",
                        " && @.type != \"MENU\"",
                        " && @.type != \"MONTH_YEAR\"",
                        " && @.type != \"OTP\"",
                        " && @.type != \"PHONE\"",
                        " && @.type != \"REFERENCE\"",
                        " && @.type != \"URL\"",
                        ")]"
                    )),
                    value_path: String::from("$.value"),
                    name: SecretNameSource::Path {
                        path: String::from("$.label"),
                    },
                    // $.title is the item name (e.g. "GitHub"); broadcast to
                    // every extracted field to form the two-segment placeholder
                    // firma-secret://1password/{item}/{name}.
                    item_selector: Some(SecretJsonSelector {
                        path: String::from("$.title"),
                        scope: SecretJsonSelectorScope::Document,
                    }),
                    // Selects every URL for the whole item; rewrite_json
                    // normalizes and deduplicates them, then broadcasts the
                    // resulting domain set to every extracted field value.
                    domain_selector: Some(SecretJsonSelector {
                        path: String::from("$.urls[*].href"),
                        scope: SecretJsonSelectorScope::Document,
                    }),
                },
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("whoami")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("account"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("vault"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("item"), String::from("list")],
            }),
        ],
        strip_arg_flags: vec![String::from("--format")],
        forced_args: vec![String::from("--format"), String::from("json")],
    }
}

// `vault kv get -format=json` on a KV v2 mount returns
// `{"data":{"data":{<name>: <value>, ...},"metadata":{...}}}`. Unlike
// `bws`/`op`, the secret's name here is the JSON object key itself — there is
// no separate name/label field anywhere in the document for a name JSONPath
// to select — so this uses `SecretNameSource::RecordKey` to derive the name
// from each record's own location instead. We force JSON output (as `op`
// does) so the record-key extraction always sees this shape.
//
// `kv list`/`list`/`status`/`policy list` return key names, path listings, or
// cluster/policy metadata — no secret values — so they pass through
// unredacted rather than needing a matcher.
//
// Any non-`kv` `vault read` target (policies, transit keys, auth config,
// etc.) uses a `read` subcommand, not `kv get`. It is explicitly blocked
// below rather than left to the implicit fail-closed default, since it is a
// real, documented retrieval path.
//
// Remaining gap `args_match` can't close: `vault kv get` on a KV v1 mount
// uses the same subcommand as v2 but returns `data` without the nested
// `data` wrapper, so `record_path` selects no records there; `vault kv get
// -field=<name> ...` matches the same prefix but prints a bare value with no
// JSON at all. Both still match `kv get` and reach the matcher, so both
// surface a `MatcherError` at extraction time rather than being blocked
// upfront or leaking unredacted.
fn vault_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("vault"),
        provider_id: String::from("hashicorp-vault"),
        credential_env_vars: vec![
            String::from("VAULT_TOKEN"),
            String::from("VAULT_ADDR"),
            String::from("VAULT_NAMESPACE"),
        ],
        matchers: vec![
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("read")],
            }),
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("kv"), String::from("get")],
                matcher: SecretMatcher::Json {
                    record_path: String::from("$.data.data.*"),
                    value_path: String::from("$"),
                    name: SecretNameSource::RecordKey,
                    item_selector: None,
                    domain_selector: None,
                },
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("status")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("policy"), String::from("list")],
            }),
        ],
        // Strip any -format/-format= flag and force JSON, regardless of what
        // the agent requested.
        strip_arg_flags: vec![String::from("-format"), String::from("--format")],
        forced_args: vec![String::from("-format"), String::from("json")],
    }
}

// `doppler secrets download --format env` outputs NAME=VALUE pairs, one per
// line. We force this format so the regex always has a well-defined input
// shape.
//
// `me`/`projects list`/`environments list`/`configs list` return account or
// project/environment/config metadata — no secret values — so they pass
// through unredacted rather than needing a matcher.
//
// `doppler run -- <command>` injects secrets as env vars for a child process
// and never prints them; `doppler secrets get <name>` (with or without
// `--plain`) either prints a bare value with no `=` for the regex to anchor
// on, or a table with no forced structured format. Both are explicitly
// blocked below rather than left to the implicit fail-closed default, since
// they are real, documented retrieval paths distinct from `secrets
// download`.
fn doppler_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("doppler"),
        provider_id: String::from("doppler"),
        credential_env_vars: vec![String::from("DOPPLER_TOKEN")],
        matchers: vec![
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("run")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("get")],
            }),
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("secrets"), String::from("download")],
                matcher: SecretMatcher::Regex {
                    pattern: String::from(r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.+)$"),
                },
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("me")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("projects"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("environments"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("configs"), String::from("list")],
            }),
        ],
        strip_arg_flags: vec![String::from("--format")],
        forced_args: vec![String::from("--format"), String::from("env")],
    }
}
