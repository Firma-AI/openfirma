//! [`CredentialInjector`](super::CredentialInjector) providers

mod basic;
mod composite;
mod vault;

pub use basic::BasicCredentialInjector;
pub use composite::CompositeCredentialInjector;
pub use vault::{VaultCredentialInjector, VaultSecretEntry};
