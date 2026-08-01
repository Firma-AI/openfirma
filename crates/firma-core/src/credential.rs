//! Credential bundle types shared between the sidecar and connector
//! implementations.
//!
//! The sidecar runs credential injection after enforcement passes and
//! produces an [`InjectedCredentials`] value. That value is handed to
//! connectors (in-tree or out-of-tree) through a [`TransportView`] so
//! they can merge the injected headers into the outbound request.
//!
//! Only the read-only bundle lives here. The [`CredentialInjector`]
//! trait and its implementations stay inside `firma-sidecar` because
//! they are consumed only by the enforcement pipeline.
//!
//! [`CredentialInjector`]: https://docs.rs/firma-sidecar/latest/firma_sidecar/credential/trait.CredentialInjector.html
//! [`TransportView`]: crate::transport::TransportView

use std::collections::HashMap;

use firma_http::HeaderName;

/// Read-only bundle of headers injected into an outbound request after
/// enforcement passes.
///
/// Produced by the sidecar credential injection stage. Contains only
/// HTTP headers — the originating [`ExecutionEnvelope`] is never
/// mutated. Connectors merge these headers into the outbound request.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use firma_core::InjectedCredentials;
/// use firma_http::HeaderName;
///
/// let mut creds = InjectedCredentials::empty();
/// creds.insert(HeaderName::from_static("authorization"), "Bearer tok".to_string());
/// assert_eq!(
///     creds.get(&HeaderName::from_static("authorization")).map(String::as_str),
///     Some("Bearer tok"),
/// );
/// ```
///
/// [`ExecutionEnvelope`]: crate::ExecutionEnvelope
#[derive(Debug, Clone)]
pub struct InjectedCredentials {
    headers: HashMap<HeaderName, String>,
}

impl InjectedCredentials {
    /// Creates a new [`InjectedCredentials`] from a header map.
    #[must_use]
    pub fn new(headers: HashMap<HeaderName, String>) -> Self {
        Self { headers }
    }

    /// Creates an empty [`InjectedCredentials`] with no headers.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    /// Returns a reference to the injected headers.
    #[must_use]
    pub fn headers(&self) -> &HashMap<HeaderName, String> {
        &self.headers
    }

    /// Returns the value for a single header key, if present.
    #[must_use]
    pub fn get(&self, key: &HeaderName) -> Option<&String> {
        self.headers.get(key)
    }

    /// Inserts a header key-value pair, replacing any existing value.
    pub fn insert(&mut self, key: HeaderName, value: String) {
        self.headers.insert(key, value);
    }

    /// Returns `true` if no headers were injected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

impl From<HashMap<HeaderName, String>> for InjectedCredentials {
    fn from(headers: HashMap<HeaderName, String>) -> Self {
        Self { headers }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injected_credentials_new() {
        let headers = HashMap::from([(
            HeaderName::from_static("authorization"),
            "Bearer tok".to_string(),
        )]);
        let creds = InjectedCredentials::new(headers.clone());
        assert_eq!(creds.headers(), &headers);
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_injected_credentials_empty() {
        let creds = InjectedCredentials::empty();
        assert!(creds.is_empty());
        assert!(creds.headers().is_empty());
    }

    #[test]
    fn test_injected_credentials_from_hashmap() {
        let headers = HashMap::from([(HeaderName::from_static("x-api-key"), "key123".to_string())]);
        let creds = InjectedCredentials::from(headers.clone());
        assert_eq!(creds.headers(), &headers);
    }

    #[test]
    fn test_injected_credentials_get() {
        let creds = InjectedCredentials::new(HashMap::from([(
            HeaderName::from_static("authorization"),
            "Bearer tok".to_string(),
        )]));
        assert_eq!(
            creds
                .get(&HeaderName::from_static("authorization"))
                .map(String::as_str),
            Some("Bearer tok"),
        );
        assert!(creds.get(&HeaderName::from_static("missing")).is_none());
    }

    #[test]
    fn test_injected_credentials_insert() {
        let mut creds = InjectedCredentials::empty();
        creds.insert(HeaderName::from_static("x-key"), "val".to_string());
        assert_eq!(
            creds
                .get(&HeaderName::from_static("x-key"))
                .map(String::as_str),
            Some("val")
        );
        assert!(!creds.is_empty());
    }

    #[test]
    fn test_injected_credentials_debug() {
        let creds = InjectedCredentials::empty();
        let debug = format!("{creds:?}");
        assert!(debug.contains("InjectedCredentials"));
    }
}
