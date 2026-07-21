/// Vault-backed credential provider that reads secrets from the local
/// filesystem.
///
/// Designed for the Vault Agent sidecar pattern: Vault Agent renders
/// secret templates to local files, and this provider reads them on
/// demand. No network calls happen on the hot path — only filesystem
/// reads.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use firma_core::{ExecutionEnvelope, InjectedCredentials};
use firma_http::HeaderName;

use crate::credential::provider::{CredentialValueTransform, render_secret_value};
use crate::credential::{CredentialInjectionError, CredentialInjector};

/// Descriptor for a single credential file rendered by Vault Agent.
///
/// Each entry maps a connector ID to a file on disk that contains
/// the secret value, plus the header name under which to inject it.
#[derive(Debug, Clone)]
pub struct VaultSecretEntry {
    /// HTTP header name to inject (e.g. `Authorization`).
    pub header_name: HeaderName,
    /// Optional prefix prepended to the raw file content
    /// (e.g. `"Bearer "` to produce `Authorization: Bearer <token>`).
    pub value_prefix: Option<String>,
    /// Optional transform applied to the raw file content before injection.
    pub value_transform: Option<CredentialValueTransform>,
    /// Path to the file containing the secret value, rendered by
    /// Vault Agent.
    pub secret_path: PathBuf,
}

/// Credential injector that reads Vault Agent–rendered secret files.
///
/// Connector IDs are mapped to one or more [`VaultSecretEntry`]
/// descriptors at construction time. On each `inject()` call the
/// referenced files are read from disk, producing the header set
/// for the outbound request.
#[derive(Debug, Clone)]
pub struct VaultCredentialInjector {
    /// `connector_id` to list of secret entries.
    entries: HashMap<String, Vec<VaultSecretEntry>>,
}

impl VaultCredentialInjector {
    /// Creates a new injector from a pre-built mapping of connector
    /// IDs to secret entry lists.
    #[must_use]
    pub fn new(entries: HashMap<String, Vec<VaultSecretEntry>>) -> Self {
        Self { entries }
    }

    /// Creates an empty injector with no configured connectors.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Registers secret entries for a connector ID, replacing any
    /// previous configuration.
    pub fn insert(&mut self, connector_id: String, secrets: Vec<VaultSecretEntry>) {
        self.entries.insert(connector_id, secrets);
    }

    /// Returns the number of configured connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no connectors are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Reads a secret file and returns the trimmed content.
fn read_secret_file(path: &Path) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string())
}

#[async_trait]
impl CredentialInjector for VaultCredentialInjector {
    async fn inject(
        &self,
        _envelope: &ExecutionEnvelope,
        connector_id: &str,
        _target: &str,
    ) -> Result<InjectedCredentials, CredentialInjectionError> {
        let secrets = self.entries.get(connector_id).ok_or_else(|| {
            CredentialInjectionError::UnknownConnector {
                connector_id: connector_id.to_string(),
            }
        })?;

        let mut headers = HashMap::with_capacity(secrets.len());
        for entry in secrets {
            let raw = read_secret_file(&entry.secret_path).map_err(|e| {
                CredentialInjectionError::FetchFailed {
                    connector_id: connector_id.to_string(),
                    reason: format!(
                        "failed to read secret file '{}': {e}",
                        entry.secret_path.display()
                    ),
                }
            })?;
            let value =
                render_secret_value(&raw, entry.value_prefix.as_deref(), entry.value_transform);
            headers.insert(entry.header_name.clone(), value);
        }

        Ok(InjectedCredentials::new(headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firma_core::{ActionParams, ExecutionIntent, ExecutionMetadata, HttpMethod, HttpParams};
    use std::io::Write as _;

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
                agent_id: "agt_01j0000000e008000000000001"
                    .parse()
                    .expect("literal agent id"),
                timestamp: chrono::Utc::now(),
                trace_id: None,
                budget_consumed: 0.0,
                risk_score: None,
                thread_id: None,
                parent_action_id: None,
            },
            None,
        )
    }

    fn write_secret_file(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).expect("create secret file");
        f.write_all(content.as_bytes()).expect("write secret file");
        path
    }

    #[test]
    fn test_vault_injector_empty() {
        let injector = VaultCredentialInjector::empty();
        assert!(injector.is_empty());
        assert_eq!(injector.len(), 0);
    }

    #[test]
    fn test_vault_injector_insert_and_len() {
        let mut injector = VaultCredentialInjector::empty();
        injector.insert(
            "stripe".to_string(),
            vec![VaultSecretEntry {
                header_name: HeaderName::from_static("authorization"),
                value_prefix: Some("Bearer ".to_string()),
                value_transform: None,
                secret_path: PathBuf::from("/tmp/fake"),
            }],
        );
        assert_eq!(injector.len(), 1);
        assert!(!injector.is_empty());
    }

    #[tokio::test]
    async fn test_vault_injector_reads_secret_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let secret_path = write_secret_file(&dir, "stripe_token", "sk_live_abc123\n");

        let injector = VaultCredentialInjector::new(HashMap::from([(
            "stripe".to_string(),
            vec![VaultSecretEntry {
                header_name: HeaderName::from_static("authorization"),
                value_prefix: Some("Bearer ".to_string()),
                value_transform: None,
                secret_path,
            }],
        )]));

        let envelope = sample_envelope();
        let creds = injector
            .inject(&envelope, "stripe", "https://api.stripe.com")
            .await
            .expect("should read secret");
        assert_eq!(
            creds
                .get(&HeaderName::from_static("authorization"))
                .map(String::as_str),
            Some("Bearer sk_live_abc123")
        );
    }

    #[tokio::test]
    async fn test_vault_injector_no_prefix() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let secret_path = write_secret_file(&dir, "api_key", "key123");

        let injector = VaultCredentialInjector::new(HashMap::from([(
            "svc".to_string(),
            vec![VaultSecretEntry {
                header_name: HeaderName::from_static("x-api-key"),
                value_prefix: None,
                value_transform: None,
                secret_path,
            }],
        )]));

        let envelope = sample_envelope();
        let creds = injector
            .inject(&envelope, "svc", "https://svc.example.com")
            .await
            .expect("should read secret");
        assert_eq!(
            creds
                .get(&HeaderName::from_static("x-api-key"))
                .map(String::as_str),
            Some("key123")
        );
    }

    #[tokio::test]
    async fn test_vault_injector_multiple_headers() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let token_path = write_secret_file(&dir, "token", "tok_abc");
        let key_path = write_secret_file(&dir, "key", "key_xyz");

        let injector = VaultCredentialInjector::new(HashMap::from([(
            "multi".to_string(),
            vec![
                VaultSecretEntry {
                    header_name: HeaderName::from_static("authorization"),
                    value_prefix: Some("Bearer ".to_string()),
                    value_transform: None,
                    secret_path: token_path,
                },
                VaultSecretEntry {
                    header_name: HeaderName::from_static("x-api-key"),
                    value_prefix: None,
                    value_transform: None,
                    secret_path: key_path,
                },
            ],
        )]));

        let envelope = sample_envelope();
        let creds = injector
            .inject(&envelope, "multi", "https://example.com")
            .await
            .expect("should read both secrets");
        assert_eq!(
            creds
                .get(&HeaderName::from_static("authorization"))
                .map(String::as_str),
            Some("Bearer tok_abc")
        );
        assert_eq!(
            creds
                .get(&HeaderName::from_static("x-api-key"))
                .map(String::as_str),
            Some("key_xyz")
        );
    }

    #[tokio::test]
    async fn test_vault_injector_unknown_connector() {
        let injector = VaultCredentialInjector::empty();
        let envelope = sample_envelope();
        let result = injector
            .inject(&envelope, "nope", "https://example.com")
            .await;
        assert!(matches!(
            result,
            Err(CredentialInjectionError::UnknownConnector { .. })
        ));
    }

    #[tokio::test]
    async fn test_vault_injector_missing_file() {
        let injector = VaultCredentialInjector::new(HashMap::from([(
            "broken".to_string(),
            vec![VaultSecretEntry {
                header_name: HeaderName::from_static("authorization"),
                value_prefix: None,
                value_transform: None,
                secret_path: PathBuf::from("/nonexistent/path/secret"),
            }],
        )]));

        let envelope = sample_envelope();
        let result = injector
            .inject(&envelope, "broken", "https://example.com")
            .await;
        assert!(matches!(
            result,
            Err(CredentialInjectionError::FetchFailed { .. })
        ));
    }

    #[test]
    fn test_vault_injector_debug() {
        let injector = VaultCredentialInjector::empty();
        let debug = format!("{injector:?}");
        assert!(debug.contains("VaultCredentialInjector"));
    }

    #[test]
    fn test_vault_secret_entry_debug() {
        let entry = VaultSecretEntry {
            header_name: HeaderName::from_static("authorization"),
            value_prefix: Some("Bearer ".to_string()),
            value_transform: None,
            secret_path: PathBuf::from("/tmp/secret"),
        };
        let debug = format!("{entry:?}");
        assert!(debug.contains("VaultSecretEntry"));
    }
}
