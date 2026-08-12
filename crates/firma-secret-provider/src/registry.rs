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
//! A [`MatcherRule::SensitiveCommand`] is a known secret-emitting shape
//! (extract and redact); a [`MatcherRule::SafeCommand`] is a known-safe
//! pass-through (e.g. a `list` subcommand that only ever returns names/ids,
//! never secret values); a [`MatcherRule::BlockedCommand`] is a known
//! secret-emitting shape this registry has no way to extract or redact from
//! (e.g. a subcommand that injects secrets as env vars for a child process,
//! or prints a bare secret value with no structure a matcher can anchor on)
//! and is therefore forbidden outright rather than forwarded unredacted. Per
//! [`CliIntegrationSpec::resolve_args`](crate::spec::cli::CliIntegrationSpec::resolve_args),
//! blocked commands are checked first, then sensitive, then safe; an
//! invocation whose args match none of the three is also
//! [`MatchingResolution::Blocked`](crate::spec::MatchingResolution::Blocked)
//! — fail closed by default, on the assumption that an unrecognized invocation
//! shape may emit secret material this registry has no way to extract or
//! redact. See the comments on each built-in's individual rules below for
//! the specific retrieval paths explicitly blocked or implicitly closed off
//! for that tool, and for the remaining gaps that `args_match` alone can't
//! close (a subcommand whose *shape* is recognized but whose output doesn't
//! fit the matcher, e.g. `vault kv get` against a KV v1 mount).

use std::collections::BTreeMap;

use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher, SecretNameSource};

use crate::{
    non_empty::vec::non_empty_vec,
    spec::{
        MatcherRule,
        cli::{ArgsAndMatcher, ArgsOnly, CliIntegrationSpec, FlagValue, StripFlag},
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

fn bws_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("bws"),
        provider_id: String::from("bitwarden"),
        credential_env_vars: vec![String::from("BWS_ACCESS_TOKEN")],
        // `--server-url` (short `-u`) redirects the CLI at an arbitrary
        // server, which would send `BWS_ACCESS_TOKEN` to a host of the
        // agent's choosing on the very next request — stripped
        // unconditionally regardless of which rule below matches. `bws` is
        // a clap-based CLI, so its short `-u` alias accepts a value
        // concatenated directly onto it with no separator (e.g.
        // `-uhttps://attacker.example`); a bare-string entry only catches
        // `-u https://...`/`-u=https://...`, so this needs the explicit
        // `Concatenated` shape to close that gap too.
        //
        // `--config-file` (short `-f`) is a second, independent way to reach
        // the same outcome even with `--server-url`/`-u` stripped: per
        // `bws`'s own docs, `bws config server-base <url> --config-file
        // <path>` persists a server URL into that file, and any later
        // invocation naming the same `--config-file` uses it as the default
        // whenever `--server-url` isn't passed. An agent that already has
        // filesystem access (the very thing this sidecar is meant to
        // mediate) can write such a file itself, with no `bws` invocation of
        // its own required, then pass `--config-file`/`-f` to an
        // otherwise-permitted command — so this must be stripped too,
        // clap-concatenated short form included.
        strip_arg_flags: vec![
            StripFlag::shaped("--server-url", Some("-u"), FlagValue::Concatenated),
            StripFlag::shaped("--config-file", Some("-f"), FlagValue::Concatenated),
        ],
        matchers: vec![
            // Injects secrets as env vars for a child process and never
            // prints them.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("run")],
            }),
            // `secret create`/`edit` echo the secret value back, but there's
            // no matcher shape for it here.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secret"), String::from("create")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secret"), String::from("edit")],
            }),
            // `secret delete`/`project create`/`project edit`/`project
            // delete` are writes with no secret-value output, but are
            // blocked explicitly rather than left to the implicit
            // fail-closed default: each is a real, documented subcommand
            // this registry has no matcher for, and an explicit rule
            // documents that deliberately rather than leaving it
            // indistinguishable from a genuinely unrecognized invocation.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secret"), String::from("delete")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("create")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("edit")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("delete")],
            }),
            // `bws secret list` returns a JSON array of secret records;
            // `bws secret get <id>` returns a single record, unwrapped. Same
            // binary, same flat record shape, but the matcher's record_path
            // depends on which subcommand was invoked.
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
                // Strip both the long and short forms of the output flag
                // (`bws` declares `-o` as a documented alias for `--output`).
                // Like `-u`/`--server-url` above, `bws`'s short `-o` accepts
                // a value concatenated directly onto it with no separator
                // (e.g. `-otsv`); `Concatenated` closes that gap here too, so
                // an unstripped `-otsv` can't survive alongside the forced
                // `--output json` and skew or defeat it.
                strip_arg_flags: vec![StripFlag::shaped(
                    "--output",
                    Some("-o"),
                    FlagValue::Concatenated,
                )],
                forced_args: vec![String::from("--output"), String::from("json")],
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
                strip_arg_flags: vec![StripFlag::shaped(
                    "--output",
                    Some("-o"),
                    FlagValue::Concatenated,
                )],
                forced_args: vec![String::from("--output"), String::from("json")],
            }),
            // `project list`/`project get` return only project
            // id/name/organizationId — no secret material — so they pass
            // through unredacted rather than needing a matcher.
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("list")],
            }),
            MatcherRule::SafeCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("project"), String::from("get")],
            }),
        ],
    }
}

fn op_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("op"),
        provider_id: String::from("1password"),
        credential_env_vars: vec![String::from("OP_SERVICE_ACCOUNT_TOKEN")],
        // `op` has no documented flag that sets an API host directly — a
        // service-account token is generally understood to be self-routing
        // (it authenticates against 1Password's own cloud API regardless of
        // local state), unlike the other three built-ins' credentials. That
        // said, `op`'s own docs describe connection configuration as
        // "managed through the `--config` directory", and we could not fully
        // rule out that directory influencing request routing even under
        // service-account auth. Given that uncertainty, `--config` is
        // stripped defensively rather than assumed safe — same fail-closed
        // bias as the rest of this registry.
        strip_arg_flags: vec![StripFlag::from("--config")],
        matchers: vec![
            // Prints the raw secret as plain text, not JSON.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("read")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("inject")],
            }),
            // `document get <id>` prints a document's raw file bytes to
            // stdout (or writes them to disk via `-o/--out-file`) with no
            // JSON structure either; `document create` uploads a new
            // document. Both are explicitly blocked rather than left to the
            // implicit fail-closed default, since they are real, documented
            // retrieval (or write) paths.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("document")],
            }),
            // `op item get <item> --format json` returns a single item
            // object. Field types 1Password documents as non-secret
            // metadata (ADDRESS, CREDIT_CARD_TYPE, DATE, EMAIL, GENDER,
            // MENU, MONTH_YEAR, PHONE, REFERENCE, URL) are left unchanged.
            // OTP is also left unchanged so the numeric one-time code
            // remains usable. STRING fields are redacted because custom
            // text fields may hold sensitive material such as recovery
            // codes. Fail closed: an unrecognized `type` — including any
            // field type 1Password adds after this list was written — falls
            // through the exclusion and is treated as a secret and
            // redacted, even if it turns out not to need it.
            //
            // Remaining gap `args_match` can't close: `op item get <id>
            // --fields ...` (and `--otp`, `--share-link`) still match the
            // `item get` prefix and reach this matcher, but change the
            // output shape away from the full item object `record_path`
            // expects — a field-scoped value or bare string instead of
            // `{"fields": [...]}`. Same category as vault's KV v1 gap: it
            // surfaces a `MatcherError` at extraction time rather than
            // being pre-blocked or leaking unredacted.
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
                    // every extracted field, for now for debugging purposes only.
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
                strip_arg_flags: vec![StripFlag::from("--format")],
                forced_args: vec![String::from("--format"), String::from("json")],
            }),
            // `whoami`/`account list`/`vault list`/`item list` return
            // account, vault, or item metadata (ids, titles, categories)
            // with no field values, so they pass through unredacted rather
            // than needing a matcher.
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
    }
}

fn vault_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("vault"),
        provider_id: String::from("hashicorp-vault"),
        credential_env_vars: vec![
            String::from("VAULT_TOKEN"),
            String::from("VAULT_ADDR"),
            String::from("VAULT_NAMESPACE"),
        ],
        // `-address`/`--address` (Vault's Go flag parser accepts either
        // dash style for the same flag) redirect the CLI at an arbitrary
        // server, which would send `VAULT_TOKEN` there on the next request.
        // `-tls-skip-verify`, `-ca-cert`, `-ca-path`, `-client-cert`, and
        // `-client-key` don't change the target host by themselves, but let
        // an agent make the CLI accept a spoofed TLS identity for whatever
        // host it's later redirected to (skip verification outright, trust
        // an attacker-supplied CA, or present attacker-supplied client
        // creds) — combined with `-address`, or with DNS/network-level
        // redirection the sidecar can't see from here, that's the same
        // token-exfiltration path. `-tls-server-name` overrides the SNI/cert
        // hostname checked during that handshake and is stripped alongside
        // them for the same reason. All are stripped unconditionally
        // regardless of which rule below matches. `-tls-skip-verify` takes
        // no value at all (`FlagValue::None`): without that, the arity-blind
        // default would treat the very next positional as its value and
        // silently drop it too — e.g. `vault kv get -tls-skip-verify
        // secret/foo` would lose `secret/foo` rather than merely stripping
        // the flag.
        strip_arg_flags: vec![
            StripFlag::shaped("-address", Some("--address"), FlagValue::SeparateOrEquals),
            StripFlag::shaped(
                "-tls-skip-verify",
                Some("--tls-skip-verify"),
                FlagValue::None,
            ),
            StripFlag::shaped("-ca-cert", Some("--ca-cert"), FlagValue::SeparateOrEquals),
            StripFlag::shaped("-ca-path", Some("--ca-path"), FlagValue::SeparateOrEquals),
            StripFlag::shaped(
                "-client-cert",
                Some("--client-cert"),
                FlagValue::SeparateOrEquals,
            ),
            StripFlag::shaped(
                "-client-key",
                Some("--client-key"),
                FlagValue::SeparateOrEquals,
            ),
            StripFlag::shaped(
                "-tls-server-name",
                Some("--tls-server-name"),
                FlagValue::SeparateOrEquals,
            ),
        ],
        matchers: vec![
            // Any non-`kv` `vault read` target (policies, transit keys, auth
            // config, etc.) uses this subcommand, not `kv get`, so there is
            // no matcher shape for it here.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("read")],
            }),
            // `kv put`/`patch`/`delete`/`destroy`/`rollback`/`undelete` are
            // writes with no secret-value output; `kv metadata` returns
            // version and custom-metadata JSON, not secret values. None of
            // these emit the `data.data` shape the matcher below expects,
            // so all are explicitly blocked rather than left to the
            // implicit fail-closed default: each is a real, documented
            // subcommand this registry has no matcher for, and an explicit
            // rule documents that deliberately.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("put")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("patch")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("delete")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("destroy")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("rollback")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("undelete")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("kv"), String::from("metadata")],
            }),
            // `vault kv get -format=json` on a KV v2 mount returns
            // `{"data":{"data":{<name>: <value>, ...},"metadata":{...}}}`.
            // Unlike `bws`/`op`, the secret's name here is the JSON object
            // key itself — there is no separate name/label field anywhere
            // in the document for a name JSONPath to select — so this uses
            // `SecretNameSource::RecordKey` to derive the name from each
            // record's own location instead. We force JSON output (as `op`
            // does) so the record-key extraction always sees this shape.
            //
            // Remaining gaps `args_match` can't close: `vault kv get` on a
            // KV v1 mount uses the same subcommand as v2 but returns `data`
            // without the nested `data` wrapper, so `record_path` selects
            // no records there; `vault kv get -field=<name> ...` matches
            // the same prefix but prints a bare value with no JSON at all;
            // `vault kv get -output-curl-string ...` matches the same
            // prefix but prints a `curl` command line containing the live
            // `VAULT_TOKEN` credential, not JSON. All three still match `kv
            // get` and reach the matcher, so all surface a `MatcherError`
            // at extraction time rather than being blocked upfront or
            // leaking unredacted.
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("kv"), String::from("get")],
                matcher: SecretMatcher::Json {
                    record_path: String::from("$.data.data.*"),
                    value_path: String::from("$"),
                    name: SecretNameSource::RecordKey,
                    item_selector: None,
                    domain_selector: None,
                },
                // Strip any -format/-format= flag and force JSON, regardless
                // of what the agent requested.
                strip_arg_flags: vec![StripFlag::shaped(
                    "-format",
                    Some("--format"),
                    FlagValue::SeparateOrEquals,
                )],
                forced_args: vec![String::from("-format"), String::from("json")],
            }),
            // `kv list`/`list`/`status`/`policy list` return key names,
            // path listings, or cluster/policy metadata — no secret
            // values — so they pass through unredacted rather than needing
            // a matcher.
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
    }
}

fn doppler_spec() -> CliIntegrationSpec {
    CliIntegrationSpec {
        binary_name: String::from("doppler"),
        provider_id: String::from("doppler"),
        credential_env_vars: vec![String::from("DOPPLER_TOKEN")],
        // `--api-host` redirects the CLI at an arbitrary API host, which
        // would send `DOPPLER_TOKEN` there on the next request;
        // `--no-verify-tls` disables TLS certificate verification, letting
        // that redirected host present a spoofed certificate. Both are
        // stripped unconditionally regardless of which rule below matches.
        // `--no-verify-tls` takes no value (`FlagValue::None`) so the
        // arity-blind default doesn't swallow whatever positional follows it.
        //
        // `--config-dir` is a second, independent redirection path even with
        // `--api-host`/`--no-verify-tls` stripped: Doppler persists
        // `api-host`/`verify-tls` per scope in that directory's
        // `.doppler.yaml`, so an agent with filesystem access (the very
        // thing this sidecar mediates) can write its own config directory
        // and point an otherwise-permitted command at it, with no `doppler`
        // invocation of its own required to set it up first. No documented
        // short alias, per the CLI's own `root.go` flag registration.
        strip_arg_flags: vec![
            StripFlag::from("--api-host"),
            StripFlag::shaped("--no-verify-tls", None, FlagValue::None),
            StripFlag::from("--config-dir"),
        ],
        matchers: vec![
            // Injects secrets as env vars for a child process and never
            // prints them.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("run")],
            }),
            // `secrets get <name>` (with or without `--plain`) either
            // prints a bare value with no structure for the matcher to
            // anchor on, or a table with no forced structured format —
            // there's no shape here for a matcher to extract from.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("get")],
            }),
            // `secrets substitute <template> --output <file>` renders
            // secret values into an arbitrary template file, writing into a
            // caller-chosen file rather than stdout.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("substitute")],
            }),
            // `secrets set`/`secrets upload`/`secrets delete` mutate secrets
            // (write real state to Doppler) rather than just reading them.
            // None of the three are blocked as an artifact of the implicit
            // fail-closed default — they must be listed explicitly, because
            // without an explicit block they'd match the bare `secrets`
            // `SensitiveCommand` rule below (a single-token `args_match`
            // that matches any `secrets ...` invocation not already claimed
            // by a more specific rule) and be routed through
            // Sensitive-command execution: the subprocess call — and the
            // mutation it performs — happens before extraction gets a
            // chance to fail closed on the mismatched output shape.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("set")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("upload")],
            }),
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("delete")],
            }),
            // `secrets notes` (per the CLI's own `secrets_notes.go`) has
            // exactly one real subcommand today, `set` — also a mutation —
            // but is blocked here as the two-token *prefix* `["secrets",
            // "notes"]` rather than the three-token `["secrets", "notes",
            // "set"]` this used to be: anything else under `notes` (a
            // version adds later, or simply a typo/unsupported invocation
            // like `notes get`) would otherwise fall through to the same
            // bare-`secrets` catch-all described above — that command
            // shape doesn't exist in the CLI today, so it fails at the
            // CLI's own argument-count validation before any HTTP call is
            // made, but relying on that rather than blocking here would tie
            // this registry's safety to the *current* absence of a `notes
            // get`/`notes delete` command instead of stating outright that
            // nothing under `notes` should ever reach Sensitive-command
            // execution.
            MatcherRule::BlockedCommand(ArgsOnly {
                args_match: non_empty_vec![String::from("secrets"), String::from("notes")],
            }),
            // `doppler secrets download --format json --no-file` outputs a
            // flat JSON object of `{name: value, ...}` pairs, the same
            // shape `vault kv get` extracts via `RecordKey` naming (minus
            // the `data.data` wrapper). We force this format (json is
            // already the CLI's own default, but an agent could still
            // request `env`) so the matcher always sees a structurally
            // parseable shape — unlike a byte-level regex, this also
            // handles multi-line secret values (e.g. PEM keys) correctly,
            // since JSON escapes embedded newlines.
            //
            // `--no-file` is forced unconditionally. `secrets download`
            // accepts an optional positional `<filepath>` argument; without
            // `--no-file`, the CLI writes the (encrypted, but
            // agent-decryptable via its own `--passphrase` flag) output to
            // that file — or a default filename — instead of stdout,
            // bypassing this matcher entirely. Per the CLI's own source
            // (`downloadSecrets` in `pkg/cmd/secrets.go`), `--no-file` is
            // checked first and returns immediately after printing to
            // stdout, before the positional filepath argument is even
            // read — so forcing it here makes any file target the agent
            // supplies inert, regardless of where in argv it appears.
            //
            // `--no-file` does not touch the *fallback file*, a separate
            // side channel: with `--fallback PATH`, the CLI writes an
            // encrypted copy of every fetched secret to `PATH` after each
            // successful fetch, independent of whether the primary output
            // goes to stdout or a file. The encryption passphrase defaults
            // to one derived from the current config, but `--fallback-
            // passphrase` lets the agent set it explicitly — turning
            // `--fallback` into an exfiltration path that bypasses this
            // matcher entirely, encrypted or not, since the agent chooses
            // both the destination and the key. `--no-fallback` ("disable
            // reading and writing the fallback file") is forced
            // unconditionally to close it, and `--fallback`,
            // `--fallback-passphrase`, `--fallback-only` (implies
            // `--fallback-readonly`), `--fallback-readonly`, and `--offline`
            // (an alias for `--fallback-only`) are all stripped so none of
            // them can survive alongside the forced flag.
            //
            // Ordering matters: `resolve_args` picks the *first* matching
            // `SensitiveCommand` rule, so this longer, more specific match
            // must stay listed before bare `secrets` below — otherwise the
            // shorter matcher, which is always contained in the longer one
            // (see `args_matches`), would shadow it and route `secrets
            // download` through the wrong matcher.
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("secrets"), String::from("download")],
                matcher: SecretMatcher::Json {
                    record_path: String::from("$.*"),
                    value_path: String::from("$"),
                    name: SecretNameSource::RecordKey,
                    item_selector: None,
                    domain_selector: None,
                },
                strip_arg_flags: vec![
                    StripFlag::from("--format"),
                    StripFlag::from("--fallback"),
                    StripFlag::from("--fallback-passphrase"),
                    StripFlag::shaped("--fallback-only", None, FlagValue::None),
                    StripFlag::shaped("--fallback-readonly", None, FlagValue::None),
                    StripFlag::shaped("--offline", None, FlagValue::None),
                ],
                forced_args: vec![
                    String::from("--format"),
                    String::from("json"),
                    String::from("--no-file"),
                    String::from("--no-fallback"),
                ],
            }),
            // Bare `doppler secrets --json` (no subcommand) also emits
            // every secret in one call, in a different but equally
            // well-defined shape: per the CLI's own source
            // (`printer.Secrets` in `pkg/printer/enclave.go`), the JSON
            // branch always prints `{"<name>": {"computed": <value-or-null>,
            // "note": ..., "computedVisibility": ..., "computedValueType":
            // ...}, ...}` — so this is a `SensitiveCommand` too, not
            // blocked: `record_path: "$.*"` selects each per-secret object,
            // `value_path: "$.computed"` its value, name from the record's
            // own key. `--json` is forced (it's a persistent root flag, not
            // `secrets`-specific — this command has no `--format`); `--raw`
            // is stripped unconditionally, since passing it adds a second,
            // un-extracted secret-bearing `raw` field to every record that
            // this matcher doesn't cover. `--only-names` takes an entirely
            // different, values-free code path (`printer.SecretsNames`)
            // whose output shape doesn't match `record_path` either, so it
            // fails closed via `MatcherError` rather than leaking — same
            // class of gap as `vault kv get -field=`.
            //
            // A restricted secret with no computed value serializes
            // `"computed": null`; `value_path` requires a string, so one
            // restricted secret in the batch fails the whole extraction
            // closed (`MatcherError::NonStringNode`), same as everywhere
            // else in this registry that a single bad record voids the
            // batch rather than silently redacting only the good ones.
            MatcherRule::SensitiveCommand(ArgsAndMatcher {
                args_match: vec![String::from("secrets")],
                matcher: SecretMatcher::Json {
                    record_path: String::from("$.*"),
                    value_path: String::from("$.computed"),
                    name: SecretNameSource::RecordKey,
                    item_selector: None,
                    domain_selector: None,
                },
                strip_arg_flags: vec![
                    StripFlag::shaped("--json", None, FlagValue::None),
                    StripFlag::shaped("--raw", None, FlagValue::None),
                ],
                forced_args: vec![String::from("--json")],
            }),
            // `me`/`projects list`/`environments list`/`configs list`
            // return account or project/environment/config metadata — no
            // secret values — so they pass through unredacted rather than
            // needing a matcher.
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
    }
}
