use serde::Deserialize;

pub mod cli;
pub mod http;

/// One entry in `secret_providers`
///
/// Either a bare string naming an existing built-in integration (e.g. `"bws"`),
/// or a full table defining a new custom integration (CLI or HTTP).
/// The outer dispatch is string-vs-table; the CLI-vs-HTTP distinction *within*
/// the table form is resolved by [`SecretProviderConfig`]'s own `type` tag.
#[derive(Debug, Clone)]
pub enum SecretProviderPatch {
    Named(String),
    Custom(Box<SecretProviderConfig>),
}

impl<'de> Deserialize<'de> for SecretProviderPatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PatchVisitor;

        impl<'de> serde::de::Visitor<'de> for PatchVisitor {
            type Value = SecretProviderPatch;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(
                    "a built-in integration name (bare string) or a custom integration table tagged by `type`",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretProviderPatch::Named(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretProviderPatch::Named(value))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecretProviderPatch::Named(value.to_owned()))
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let config = SecretProviderConfig::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )
                .map_err(|error| {
                    serde::de::Error::custom(format!(
                        "invalid secret_providers entry (expected a table with `type = \"cli\"` or `type = \"http\"`): {error}"
                    ))
                })?;
                Ok(SecretProviderPatch::Custom(Box::new(config)))
            }
        }

        deserializer.deserialize_any(PatchVisitor)
    }
}

/// A custom secret-provider integration spec
///
/// One full-table entry in `secret_providers`, explicitly tagged by `type`
/// so a CLI-only field (e.g. `binary_name`) and an HTTP-only field (e.g.
/// `host`) can never be mixed on the same entry — an untagged CLI-vs-HTTP
/// guess would also give worse parse errors for a malformed table than an
/// explicit tag does.
///
/// Minimal CLI example (JSON output with `{ key, value }` pairs):
///
/// ```toml
/// [run.defaults]
/// secret_providers = [
///     { type = "cli", binary_name = "mock-vault", provider_id = "mock-vault", credential_env_vars = [], matchers = [{ type = "sensitive_command", argv = ["secret", "list"], matcher = { type = "json", record_path = "$[*]", value_path = "$.value", name = { source = "path", path = "$.key" } } }] },
/// ]
/// ```
///
/// Minimal HTTP example:
///
/// ```toml
/// [run.defaults]
/// secret_providers = [
///     { type = "http", provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", matchers = [{ type = "sensitive_command", path = "/GetSecretValue", matcher = { type = "json", record_path = "$", value_path = "$.SecretString", name = { source = "path", path = "$.Name" } } }] },
/// ]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretProviderConfig {
    Cli(cli::CliSecretProviderConfig),
    Http(http::HttpSecretProviderConfig),
}
