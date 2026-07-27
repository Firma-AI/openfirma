//! Built-in integration specs for supported CLI secret managers.
//!
//! Each spec names the vault CLI binary, lists the credential env vars the
//! broker must forward to the subprocess, specifies how to extract secrets from
//! the tool's stdout, and provides the placeholder template used to mint tokens.
//!
//! CLI-only: every built-in is a vault CLI tool. There are no built-in HTTP
//! vaults — every HTTP provider must be fully user-defined (matching how
//! custom CLI integrations already work).
//!
//! The registry is keyed by binary basename; a launcher whose basename is not in
//! the registry can still be permitted or passed through by Cedar, but no
//! intercept transform is applied (the output is forwarded unchanged).

use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher};

use crate::spec::CliIntegrationSpec;

/// Registry of CLI integration specs, keyed by binary basename.
///
/// Starts with the four built-in specs and can be extended with custom specs
/// loaded from `firma.toml` (`secret_providers` table entries). Custom specs
/// take precedence over built-ins when names collide.
#[derive(Debug, Default)]
pub struct IntegrationRegistry {
    specs: Vec<CliIntegrationSpec>,
}

impl IntegrationRegistry {
    /// Build a registry containing the built-in specs for all supported vault
    /// CLIs.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self {
            specs: vec![
                CliIntegrationSpec {
                    binary_name: String::from("bws"),
                    provider_id: String::from("bitwarden"),
                    credential_env_vars: vec![String::from("BWS_ACCESS_TOKEN")],
                    matcher: SecretMatcher::Json {
                        record_path: String::from("$[*]"),
                        value_path: String::from("$.value"),
                        name_path: String::from("$.key"),
                        item_selector: None,
                        domain_selector: None,
                    },
                    strip_arg_flags: vec![],
                    forced_args: vec![],
                },
                // `op item get <item> --format json` returns a single item
                // object. We extract only sensitive field types (CONCEALED,
                // TOTP, CREDIT_CARD_NUMBER) using a JSONPath filter expression.
                // The item's primary URL is broadcast as the domain scope for
                // all extracted fields.
                CliIntegrationSpec {
                    binary_name: String::from("op"),
                    provider_id: String::from("1password"),
                    credential_env_vars: vec![String::from("OP_SERVICE_ACCOUNT_TOKEN")],
                    matcher: SecretMatcher::Json {
                        record_path: String::from("$"),
                        value_path: String::from(concat!(
                            "$.fields[?(",
                            "@.type == \"CONCEALED\"",
                            " || @.type == \"TOTP\"",
                            " || @.type == \"CREDIT_CARD_NUMBER\"",
                            ")].value"
                        )),
                        name_path: String::from(concat!(
                            "$.fields[?(",
                            "@.type == \"CONCEALED\"",
                            " || @.type == \"TOTP\"",
                            " || @.type == \"CREDIT_CARD_NUMBER\"",
                            ")].label"
                        )),
                        // $.title is the item name (e.g. "GitHub"); broadcast
                        // to every extracted field to form the two-segment
                        // placeholder firma-secret://1password/{item}/{name}.
                        item_selector: Some(SecretJsonSelector {
                            path: String::from("$.title"),
                            scope: SecretJsonSelectorScope::Document,
                        }),
                        // Selects one URL for the whole item; rewrite_json
                        // broadcasts it to every extracted field value.
                        domain_selector: Some(SecretJsonSelector {
                            path: String::from("$.urls[0].href"),
                            scope: SecretJsonSelectorScope::Document,
                        }),
                    },
                    strip_arg_flags: vec![String::from("--format")],
                    forced_args: vec![String::from("--format"), String::from("json")],
                },
                CliIntegrationSpec {
                    binary_name: String::from("vault"),
                    provider_id: String::from("hashicorp-vault"),
                    credential_env_vars: vec![
                        String::from("VAULT_TOKEN"),
                        String::from("VAULT_ADDR"),
                        String::from("VAULT_NAMESPACE"),
                    ],
                    // vault kv get with no -format flag outputs a columnar table;
                    // the regex matches data rows (identifier + value) and skips
                    // header/separator lines that start with non-word characters.
                    matcher: SecretMatcher::Regex {
                        pattern: String::from(
                            r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_/-]*)\s{2,}(?P<value>\S+)$",
                        ),
                    },
                    // Strip any -format/-format= flag so the table-format regex
                    // is always used, regardless of what the agent requested.
                    strip_arg_flags: vec![String::from("-format"), String::from("--format")],
                    forced_args: vec![],
                },
                // `doppler secrets download --format env` outputs NAME=VALUE
                // pairs, one per line. We force this format so the regex always
                // has a well-defined input shape.
                CliIntegrationSpec {
                    binary_name: String::from("doppler"),
                    provider_id: String::from("doppler"),
                    credential_env_vars: vec![String::from("DOPPLER_TOKEN")],
                    matcher: SecretMatcher::Regex {
                        pattern: String::from(
                            r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.+)$",
                        ),
                    },
                    strip_arg_flags: vec![String::from("--format")],
                    forced_args: vec![String::from("--format"), String::from("env")],
                },
            ],
        }
    }

    /// Look up a spec by binary basename. Returns `None` for unknown tools.
    #[must_use]
    pub fn get(&self, binary_name: &str) -> Option<&CliIntegrationSpec> {
        self.specs
            .iter()
            .rev()
            .find(|spec| spec.binary_name == binary_name)
    }

    /// Add a custom spec. If a spec with the same binary name already exists
    /// (e.g. a built-in), the custom one takes precedence (is found first).
    pub fn push(&mut self, spec: CliIntegrationSpec) {
        self.specs.push(spec);
    }
}
