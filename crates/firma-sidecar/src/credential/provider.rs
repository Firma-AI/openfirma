//! [`CredentialInjector`](super::CredentialInjector) providers

mod basic;
mod composite;
mod vault;

use base64::Engine as _;

pub use basic::BasicCredentialInjector;
pub use composite::CompositeCredentialInjector;
pub use vault::{VaultCredentialInjector, VaultSecretEntry};

/// Transform applied to resolved credential values before injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialValueTransform {
    /// Convert a GitHub PAT into the Basic value accepted by Git smart HTTP.
    GithubPatBasic,
}

/// Render a resolved secret value for injection.
#[must_use]
pub fn render_secret_value(
    raw: &str,
    prefix: Option<&str>,
    transform: Option<CredentialValueTransform>,
) -> String {
    match transform {
        Some(CredentialValueTransform::GithubPatBasic) => {
            let payload = format!("x-access-token:{raw}");
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(payload)
            )
        }
        None => prefix.map_or_else(|| raw.to_string(), |prefix| format!("{prefix}{raw}")),
    }
}
