/// Composite credential injector that delegates to a basic provider
/// and a vault provider, trying basic first.
///
/// Used when the configuration mixes both `basic` and `vault` mode
/// entries. Each provider handles its own set of connector IDs.
use async_trait::async_trait;
use firma_core::{ExecutionEnvelope, InjectedCredentials};

use super::{BasicCredentialInjector, VaultCredentialInjector};
use crate::credential::{CredentialInjectionError, CredentialInjector};

/// Tries the basic provider first; if it returns
/// [`UnknownConnector`](CredentialInjectionError::UnknownConnector),
/// falls through to the vault provider.
#[derive(Debug)]
pub struct CompositeCredentialInjector {
    basic: BasicCredentialInjector,
    vault: VaultCredentialInjector,
}

impl CompositeCredentialInjector {
    /// Creates a new composite from a basic and a vault provider.
    #[must_use]
    pub const fn new(basic: BasicCredentialInjector, vault: VaultCredentialInjector) -> Self {
        Self { basic, vault }
    }
}

#[async_trait]
impl CredentialInjector for CompositeCredentialInjector {
    async fn inject(
        &self,
        envelope: &ExecutionEnvelope,
        connector_id: &str,
        target: &str,
    ) -> Result<InjectedCredentials, CredentialInjectionError> {
        match self.basic.inject(envelope, connector_id, target).await {
            Ok(creds) => Ok(creds),
            Err(CredentialInjectionError::UnknownConnector { .. }) => {
                self.vault.inject(envelope, connector_id, target).await
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::credential::provider::VaultSecretEntry;
    use firma_core::{ActionParams, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams};
    use std::collections::HashMap;
    use std::io::Write as _;
    use std::path::PathBuf;

    fn sample_envelope() -> ExecutionEnvelope {
        ExecutionEnvelope::new(
            ExecutionIntent {
                action_class: "filesystem.read".to_string(),
                resource: firma_core::ExecutionIntent::resource_map_from("https://api.example.com"),
                params: ActionParams::Http(HttpParams {
                    method: HttpMethod::GET,
                    headers: HashMap::new(),
                    body: None,
                    query: HashMap::new(),
                }),
                raw_transport: "https".to_string(),
                raw_action_ref: "GET /".to_string(),
            },
            "v4.public.eyJ0...".to_string(),
            ExecutionMetadata {
                session_id: "sess_001".parse().expect("literal session id"),
                agent_id: "agent_abc".parse().expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
            },
            None,
        )
    }

    #[tokio::test]
    async fn test_composite_basic_hit() {
        let basic = BasicCredentialInjector::new(HashMap::from([(
            "basic-host".to_string(),
            HashMap::from([("Authorization".to_string(), "Bearer basic".to_string())]),
        )]));
        let vault = VaultCredentialInjector::empty();
        let composite = CompositeCredentialInjector::new(basic, vault);

        let creds = composite
            .inject(&sample_envelope(), "basic-host", "https://basic-host")
            .await
            .expect("basic hit");
        assert_eq!(
            creds.get("Authorization").map(String::as_str),
            Some("Bearer basic")
        );
    }

    #[tokio::test]
    async fn test_composite_vault_fallback() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("secret");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"vault_tok").expect("write");
        }

        let basic = BasicCredentialInjector::empty();
        let vault = VaultCredentialInjector::new(HashMap::from([(
            "vault-host".to_string(),
            vec![VaultSecretEntry {
                header_name: "X-Api-Key".to_string(),
                value_prefix: None,
                secret_path: path,
            }],
        )]));
        let composite = CompositeCredentialInjector::new(basic, vault);

        let creds = composite
            .inject(&sample_envelope(), "vault-host", "https://vault-host")
            .await
            .expect("vault fallback");
        assert_eq!(
            creds.get("X-Api-Key").map(String::as_str),
            Some("vault_tok")
        );
    }

    #[tokio::test]
    async fn test_composite_unknown_both() {
        let composite = CompositeCredentialInjector::new(
            BasicCredentialInjector::empty(),
            VaultCredentialInjector::empty(),
        );

        let result = composite
            .inject(&sample_envelope(), "nope", "https://nope")
            .await;
        assert!(matches!(
            result,
            Err(CredentialInjectionError::UnknownConnector { .. })
        ));
    }

    #[tokio::test]
    async fn test_composite_vault_fetch_failed() {
        let basic = BasicCredentialInjector::empty();
        let vault = VaultCredentialInjector::new(HashMap::from([(
            "broken".to_string(),
            vec![VaultSecretEntry {
                header_name: "Authorization".to_string(),
                value_prefix: None,
                secret_path: PathBuf::from("/nonexistent/secret"),
            }],
        )]));
        let composite = CompositeCredentialInjector::new(basic, vault);

        let result = composite
            .inject(&sample_envelope(), "broken", "https://broken")
            .await;
        assert!(matches!(
            result,
            Err(CredentialInjectionError::FetchFailed { .. })
        ));
    }
}
