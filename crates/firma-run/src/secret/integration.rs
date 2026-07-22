//! Built-in integration specs for supported secret managers.
//!
//! Each spec names the vault CLI binary, lists the credential env vars the
//! broker must forward to the subprocess, specifies how to extract secrets from
//! the tool's stdout, and provides the placeholder template used to mint tokens.
//!
//! The registry is keyed by binary basename; a launcher whose basename is not in
//! the registry can still be permitted or passed through by Cedar, but no
//! intercept transform is applied (the output is forwarded unchanged).

use firma_core::SecretMatcher;

/// Per-tool behavior spec: credentials to forward, how to extract secrets, and
/// how to mint placeholder tokens for the extracted values.
#[derive(Debug, Clone)]
pub struct IntegrationSpec {
    /// Binary basename (e.g. `"bws"`).
    pub binary_name: &'static str,
    /// Names of env vars that carry vault credentials. The broker forwards any
    /// that are present in its own environment to the subprocess.
    pub credential_env_vars: &'static [&'static str],
    /// How to extract `(name, value)` pairs from the tool's stdout.
    pub matcher: SecretMatcher,
    /// Template for minting placeholder tokens; `{name}` is substituted with the
    /// percent-encoded secret key.
    pub placeholder_template: &'static str,
}

/// Registry of built-in integration specs, keyed by binary basename.
#[derive(Debug, Default)]
pub struct IntegrationRegistry {
    specs: Vec<IntegrationSpec>,
}

impl IntegrationRegistry {
    /// Build a registry containing the built-in specs for all supported vault
    /// CLIs.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self {
            specs: vec![
                IntegrationSpec {
                    binary_name: "bws",
                    credential_env_vars: &["BWS_ACCESS_TOKEN"],
                    matcher: SecretMatcher::Json {
                        value_path: "$[*].value".to_string(),
                        name_path: "$[*].key".to_string(),
                        domain_path: None,
                    },
                    placeholder_template: "firma-secret://bitwarden/{name}",
                },
                IntegrationSpec {
                    binary_name: "op",
                    credential_env_vars: &["OP_SERVICE_ACCOUNT_TOKEN"],
                    matcher: SecretMatcher::Json {
                        value_path: "$[*].value".to_string(),
                        name_path: "$[*].label".to_string(),
                        domain_path: Some("$[*].urls[0].href".to_string()),
                    },
                    placeholder_template: "firma-secret://1password/{name}",
                },
                IntegrationSpec {
                    binary_name: "vault",
                    credential_env_vars: &["VAULT_TOKEN", "VAULT_ADDR", "VAULT_NAMESPACE"],
                    matcher: SecretMatcher::Regex {
                        pattern: r"(?m)^(?P<name>[^=\s]+)\s+(?P<value>\S+)$".to_string(),
                    },
                    placeholder_template: "firma-secret://hashicorp-vault/{name}",
                },
                IntegrationSpec {
                    binary_name: "doppler",
                    credential_env_vars: &["DOPPLER_TOKEN"],
                    matcher: SecretMatcher::Regex {
                        pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$".to_string(),
                    },
                    placeholder_template: "firma-secret://doppler/{name}",
                },
            ],
        }
    }

    /// Look up a spec by binary basename. Returns `None` for unknown tools.
    #[must_use]
    pub fn get(&self, binary_name: &str) -> Option<&IntegrationSpec> {
        self.specs
            .iter()
            .find(|spec| spec.binary_name == binary_name)
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
        assert!(spec.credential_env_vars.contains(&"BWS_ACCESS_TOKEN"));
        assert!(spec.placeholder_template.contains("bitwarden"));
    }
}
