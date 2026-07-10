//! [`CredentialInjector`](credential::CredentialInjector) construction from the `[credentials]`
//! config section.
//!
//! Basic-mode entries resolve their `value_from_env` environment
//! variable at startup. Vault-mode entries record the `secret_path`
//! for per-call reads. When both modes are present, the resulting
//! injector tries the basic provider first, then falls back to vault.

use std::collections::HashMap;

use firma_core::HeaderName;

use crate::config;
use crate::credential;

/// Builds a [`CredentialInjector`](credential::CredentialInjector)
/// from the `[credentials]` configuration section.
///
/// If no credentials are configured, returns a
/// [`NullCredentialInjector`](credential::NullCredentialInjector).
///
/// # Errors
///
/// Returns an error if a basic-mode entry references a missing or
/// empty environment variable.
pub fn build_credential_injector<S: std::hash::BuildHasher>(
    creds: &HashMap<String, config::CredentialConfig, S>,
) -> anyhow::Result<Box<dyn credential::CredentialInjector>> {
    use config::CredentialMode;

    if creds.is_empty() {
        tracing::debug!("no credential entries configured; using null injector");
        return Ok(Box::new(credential::NullCredentialInjector));
    }

    let mut basic_map: HashMap<String, HashMap<HeaderName, String>> = HashMap::new();
    let mut vault_map: HashMap<String, Vec<credential::provider::VaultSecretEntry>> =
        HashMap::new();

    for (label, entry) in creds {
        match entry.mode {
            CredentialMode::Basic => {
                let env_name = entry.value_from_env.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("credentials.{label}: value_from_env required for basic mode")
                })?;
                let raw_value = std::env::var(env_name).map_err(|e| {
                    anyhow::anyhow!("credentials.{label}: env var '{env_name}' not set: {e}")
                })?;
                if raw_value.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "credentials.{label}: env var '{env_name}' is empty"
                    ));
                }

                let value = match &entry.prefix {
                    Some(prefix) => format!("{prefix}{raw_value}"),
                    None => raw_value,
                };

                basic_map
                    .entry(entry.target_host.clone())
                    .or_default()
                    .insert(entry.header.clone(), value);

                tracing::debug!(
                    label = label.as_str(),
                    mode = "basic",
                    target_host = entry.target_host.as_str(),
                    header = entry.header.as_str(),
                    "credential entry loaded"
                );
            }
            CredentialMode::Vault => {
                let secret_path = entry.secret_path.clone().ok_or_else(|| {
                    anyhow::anyhow!("credentials.{label}: secret_path required for vault mode")
                })?;

                vault_map
                    .entry(entry.target_host.clone())
                    .or_default()
                    .push(credential::provider::VaultSecretEntry {
                        header_name: entry.header.clone(),
                        value_prefix: entry.prefix.clone(),
                        secret_path,
                    });

                tracing::debug!(
                    label = label.as_str(),
                    mode = "vault",
                    target_host = entry.target_host.as_str(),
                    header = entry.header.as_str(),
                    "credential entry loaded"
                );
            }
        }
    }

    let has_basic = !basic_map.is_empty();
    let has_vault = !vault_map.is_empty();

    match (has_basic, has_vault) {
        (true, false) => Ok(Box::new(
            credential::provider::BasicCredentialInjector::new(basic_map),
        )),
        (false, true) => Ok(Box::new(
            credential::provider::VaultCredentialInjector::new(vault_map),
        )),
        (true, true) => Ok(Box::new(
            credential::provider::CompositeCredentialInjector::new(
                credential::provider::BasicCredentialInjector::new(basic_map),
                credential::provider::VaultCredentialInjector::new(vault_map),
            ),
        )),
        (false, false) => {
            // All entries parsed but none populated — shouldn't happen
            // given the is_empty check above, but handle defensively.
            Ok(Box::new(credential::NullCredentialInjector))
        }
    }
}
