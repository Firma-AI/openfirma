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

use firma_core::SecretMatcher;

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
                        value_path: String::from("$[*].value"),
                        name_path: String::from("$[*].key"),
                        item_path: None,
                        domain_path: None,
                        domain_is_url: false,
                    },
                    placeholder_template: String::from("firma-secret://bitwarden/{name}"),
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
                        item_path: Some(String::from("$.title")),
                        // Selects one URL for the whole item; rewrite_json
                        // broadcasts it to every extracted field value.
                        domain_path: Some(String::from("$.urls[0].href")),
                        // op stores full URLs like "https://github.com";
                        // extract only the host portion.
                        domain_is_url: true,
                    },
                    placeholder_template: String::from("firma-secret://1password/{item}/{name}"),
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
                        domain_is_url: false,
                        pattern: String::from(
                            r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_/-]*)\s{2,}(?P<value>\S+)$",
                        ),
                    },
                    placeholder_template: String::from("firma-secret://hashicorp-vault/{name}"),
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
                        domain_is_url: false,
                        pattern: String::from(
                            r"(?m)^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.+)$",
                        ),
                    },
                    placeholder_template: String::from("firma-secret://doppler/{name}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_cover_all_four_managers() {
        let registry = IntegrationRegistry::with_builtins();
        for name in ["bws", "op", "vault", "doppler"] {
            assert!(
                registry.get(name).is_some(),
                "missing built-in spec for {name}"
            );
        }
    }

    #[test]
    fn unknown_binary_returns_none() {
        let registry = IntegrationRegistry::with_builtins();
        assert!(registry.get("unknown-tool").is_none());
    }

    #[test]
    fn bws_spec_has_expected_credential_env_and_placeholder() {
        let registry = IntegrationRegistry::with_builtins();
        let spec = registry.get("bws").expect("bws spec");
        assert!(
            spec.credential_env_vars
                .iter()
                .any(|v| v == "BWS_ACCESS_TOKEN")
        );
        assert!(spec.placeholder_template.contains("bitwarden"));
    }

    #[test]
    fn push_custom_spec_takes_precedence_over_builtin() {
        let mut registry = IntegrationRegistry::with_builtins();
        registry.push(CliIntegrationSpec {
            binary_name: String::from("bws"),
            provider_id: String::from("custom"),
            credential_env_vars: vec![],
            matcher: SecretMatcher::Json {
                value_path: String::from("$[*].value"),
                name_path: String::from("$[*].key"),
                item_path: None,
                domain_path: None,
                domain_is_url: false,
            },
            placeholder_template: String::from("firma-secret://custom/{name}"),
            strip_arg_flags: vec![],
            forced_args: vec![],
        });
        let spec = registry.get("bws").expect("bws spec after push");
        assert!(spec.placeholder_template.contains("custom"));
    }
}
