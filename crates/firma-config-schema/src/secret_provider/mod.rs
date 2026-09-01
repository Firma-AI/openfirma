use serde::Deserialize;

pub mod cli;
pub mod http;

/// One entry in `secret_providers`
///
/// Either a bare string naming an existing built-in integration (e.g. `"bws"`),
/// or a full table defining a new custom integration (CLI or HTTP).
/// TOML is self-describing, so this deserializes untagged based on whether
/// the entry is a string or a table; the CLI-vs-HTTP distinction *within*
/// the table form is resolved by [`SecretProviderConfig`]'s own `type` tag,
/// not by this outer untagged split.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SecretProviderPatch {
    Named(String),
    Custom(Box<SecretProviderConfig>),
}

/// A custom secret-provider integration spec
///
/// One full-table entry in `secret_providers`, explicitly tagged by `type`
/// so a CLI-only field (e.g. `name`) and an HTTP-only field (e.g. `host`)
/// can never be mixed on the same entry — an untagged CLI-vs-HTTP guess
/// would also give worse parse errors for a malformed table than an
/// explicit tag does.
///
/// Minimal CLI example (JSON output with `{ key, value }` pairs):
///
/// ```toml
/// [run.defaults]
/// secret_providers = [
///     { type = "cli", name = "mock-vault", placeholder_template = "firma-secret://demo/{name}", matcher = { type = "json", value_path = "$[*].value", name_path = "$[*].key" } },
/// ]
/// ```
///
/// Minimal HTTP example:
///
/// ```toml
/// [run.defaults]
/// secret_providers = [
///     { type = "http", provider_id = "aws-secrets-manager", host = "secretsmanager.*.amazonaws.com", placeholder_template = "firma-secret://aws/{name}", matcher = { type = "json", value_path = "$.SecretString", name_path = "$.Name" } },
/// ]
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SecretProviderConfig {
    Cli(cli::CliSecretProviderConfig),
    Http(http::HttpSecretProviderConfig),
}
