//! HTTPS MITM runtime primitives for the HTTP proxy interceptor.
//!
//! This module owns:
//! - MITM host matching (`intercept_hosts`, `bypass_hosts`, `strict_hosts`)
//! - Sidecar CA load/generate lifecycle
//! - Per-host leaf certificate issuance and bounded cache

use std::collections::VecDeque;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use crate::config::HttpsMitmConfig;

/// Runtime state for HTTPS MITM interception.
pub struct HttpsMitmRuntime {
    config: HttpsMitmConfig,
    ca: Arc<CaMaterial>,
    cache: Mutex<LeafCertCache>,
}

impl HttpsMitmRuntime {
    /// Build MITM runtime from validated config and CA directory.
    ///
    /// # Errors
    ///
    /// Returns an error when CA key/cert generation, loading, or cache
    /// initialization fails.
    pub fn new(config: HttpsMitmConfig, ca_dir: &Path) -> Result<Self, String> {
        let ca = CaMaterial::load_or_generate(&config, ca_dir)?;
        let cache = LeafCertCache::new(config.cert_cache_capacity)?;
        Ok(Self {
            config,
            ca: Arc::new(ca),
            cache: Mutex::new(cache),
        })
    }

    /// Returns whether this host should use MITM interception.
    #[must_use]
    pub fn should_intercept_host(&self, host: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        if host_matches_any(host, &self.config.bypass_hosts) {
            return false;
        }

        host_matches_any(host, &self.config.intercept_hosts)
    }

    /// Returns whether this host is configured as strict-intercept.
    #[must_use]
    pub fn is_strict_host(&self, host: &str) -> bool {
        host_matches_any(host, &self.config.strict_hosts)
    }

    /// Build a TLS acceptor using a cached or newly-issued leaf certificate.
    ///
    /// # Errors
    ///
    /// Returns an error when certificate issuance or rustls server config
    /// construction fails.
    pub async fn tls_acceptor_for_host(&self, host: &str) -> Result<TlsAcceptor, String> {
        let normalized = normalize_host(host);
        let leaf = {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(&normalized) {
                cached
            } else {
                let created = self.issue_leaf_cert(&normalized)?;
                cache.put(normalized.clone(), created.clone());
                created
            }
        };

        let certs = vec![
            CertificateDer::from(leaf.cert_der.clone()),
            CertificateDer::from(self.ca.cert_der.clone()),
        ];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf.key_der));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to build rustls server config: {e}"))?;
        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    fn issue_leaf_cert(&self, host: &str) -> Result<CachedLeafCert, String> {
        let params = leaf_certificate_params(host)?;
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("failed to generate leaf key for {host}: {e}"))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca.cert, &self.ca.key)
            .map_err(|e| format!("failed to sign leaf certificate for {host}: {e}"))?;
        let cert_der = leaf_cert.der().to_vec();
        let key_der = leaf_key.serialize_der();
        let expires_at = Instant::now() + Duration::from_secs(self.config.cert_ttl_secs);

        Ok(CachedLeafCert {
            cert_der,
            key_der,
            expires_at,
        })
    }

    #[cfg(test)]
    async fn cache_len_for_tests(&self) -> usize {
        self.cache.lock().await.len()
    }
}

#[derive(Clone)]
struct CachedLeafCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expires_at: Instant,
}

struct LeafCertCache {
    capacity: usize,
    order: VecDeque<String>,
    entries: std::collections::HashMap<String, CachedLeafCert>,
}

impl LeafCertCache {
    fn new(capacity: usize) -> Result<Self, String> {
        if capacity == 0 {
            return Err("MITM certificate cache capacity must be > 0".to_string());
        }
        Ok(Self {
            capacity,
            order: VecDeque::new(),
            entries: std::collections::HashMap::new(),
        })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&mut self, host: &str) -> Option<CachedLeafCert> {
        let now = Instant::now();
        if let Some(entry) = self.entries.get(host).cloned() {
            if entry.expires_at > now {
                self.touch(host);
                return Some(entry);
            }
        }
        self.remove(host);
        None
    }

    fn put(&mut self, host: String, cert: CachedLeafCert) {
        if self.entries.contains_key(&host) {
            self.entries.insert(host.clone(), cert);
            self.touch(&host);
            return;
        }

        self.entries.insert(host.clone(), cert);
        self.order.push_back(host);
        self.evict_if_needed();
    }

    fn touch(&mut self, host: &str) {
        if let Some(pos) = self.order.iter().position(|h| h == host)
            && let Some(existing) = self.order.remove(pos)
        {
            self.order.push_back(existing);
        }
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn remove(&mut self, host: &str) {
        self.entries.remove(host);
        if let Some(pos) = self.order.iter().position(|h| h == host) {
            let _ = self.order.remove(pos);
        }
    }
}

struct CaMaterial {
    cert: Certificate,
    key: KeyPair,
    cert_der: Vec<u8>,
}

impl CaMaterial {
    fn load_or_generate(config: &HttpsMitmConfig, ca_dir: &Path) -> Result<Self, String> {
        let cert_path = config
            .ca_cert_path
            .clone()
            .unwrap_or_else(|| ca_dir.join("firma-ca.crt"));
        let key_path = config
            .ca_key_path
            .clone()
            .unwrap_or_else(|| ca_dir.join("firma-ca.key"));

        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create MITM cert directory {}: {e}",
                    parent.display()
                )
            })?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create MITM key directory {}: {e}",
                    parent.display()
                )
            })?;
        }

        let key_pem = if key_path.exists() {
            fs::read_to_string(&key_path)
                .map_err(|e| format!("failed to read MITM CA key {}: {e}", key_path.display()))?
        } else {
            let (_, key_pem) = generate_ca_pair()?;
            fs::write(&key_path, &key_pem)
                .map_err(|e| format!("failed to write MITM CA key {}: {e}", key_path.display()))?;
            key_pem
        };

        let ca_key =
            KeyPair::from_pem(&key_pem).map_err(|e| format!("invalid MITM CA key PEM: {e}"))?;

        let params = if cert_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path).map_err(|e| {
                format!(
                    "failed to read existing MITM CA cert {}: {e}",
                    cert_path.display()
                )
            })?;
            CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|e| {
                format!(
                    "failed to parse existing MITM CA cert {}: {e}",
                    cert_path.display()
                )
            })?
        } else {
            ca_certificate_params()
        };

        let cert = params
            .self_signed(&ca_key)
            .map_err(|e| format!("failed to build MITM CA certificate: {e}"))?;
        let cert_der = cert.der().to_vec();

        if !cert_path.exists() {
            fs::write(&cert_path, cert.pem()).map_err(|e| {
                format!(
                    "failed to write MITM CA certificate {}: {e}",
                    cert_path.display()
                )
            })?;
        }

        Ok(Self {
            cert,
            key: ca_key,
            cert_der,
        })
    }
}

fn generate_ca_pair() -> Result<(String, String), String> {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("failed to generate CA key pair: {e}"))?;
    let ca_cert = ca_certificate_params()
        .self_signed(&ca_key)
        .map_err(|e| format!("failed to generate self-signed CA cert: {e}"))?;
    let cert_pem = ca_cert.pem();
    let key_pem = ca_key.serialize_pem();
    Ok((cert_pem, key_pem))
}

fn ca_certificate_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Firma Sidecar Local CA");
    dn.push(DnType::OrganizationName, "Firma");
    params.distinguished_name = dn;
    params
}

fn leaf_certificate_params(host: &str) -> Result<CertificateParams, String> {
    let normalized = normalize_host(host);
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| format!("failed to initialize leaf certificate params: {e}"))?;
    params.is_ca = IsCa::NoCa;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, normalized.clone());
    params.distinguished_name = dn;

    if let Ok(ip) = normalized.parse::<IpAddr>() {
        params.subject_alt_names.push(SanType::IpAddress(ip));
    } else {
        let dns_name = normalized
            .clone()
            .try_into()
            .map_err(|e| format!("invalid DNS SAN '{normalized}': {e}"))?;
        params.subject_alt_names.push(SanType::DnsName(dns_name));
    }

    if params.subject_alt_names.is_empty() {
        return Err("leaf certificate requires at least one SAN".to_string());
    }

    Ok(params)
}

fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    let normalized = normalize_host(host);
    patterns
        .iter()
        .any(|pattern| wildcard_match(&normalize_host(pattern), &normalized))
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(found) => {
                if idx == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }
    if let Some(last) = parts.last()
        && !last.is_empty()
    {
        return value.ends_with(last);
    }

    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn wildcard_match_exact() {
        assert!(wildcard_match("api.openai.com", "api.openai.com"));
        assert!(!wildcard_match("api.openai.com", "x.openai.com"));
    }

    #[test]
    fn wildcard_match_suffix() {
        assert!(wildcard_match("*.openai.com", "api.openai.com"));
        assert!(!wildcard_match("*.openai.com", "openai.com"));
    }

    #[test]
    fn host_lists_apply_bypass_before_intercept() {
        let dir = tempdir().unwrap_or_else(|e| panic!("{e}"));
        let runtime = HttpsMitmRuntime::new(
            HttpsMitmConfig {
                enabled: true,
                intercept_hosts: vec!["*.openai.com".to_string()],
                bypass_hosts: vec!["api.openai.com".to_string()],
                cert_ttl_secs: 60,
                cert_cache_capacity: 8,
                ..HttpsMitmConfig::default()
            },
            dir.path(),
        )
        .unwrap_or_else(|e| panic!("{e}"));

        assert!(!runtime.should_intercept_host("api.openai.com"));
        assert!(runtime.should_intercept_host("chat.openai.com"));
    }

    #[test]
    fn strict_host_match_works() {
        let dir = tempdir().unwrap_or_else(|e| panic!("{e}"));
        let runtime = HttpsMitmRuntime::new(
            HttpsMitmConfig {
                enabled: true,
                intercept_hosts: vec!["api.openai.com".to_string()],
                strict_hosts: vec!["api.openai.com".to_string()],
                cert_ttl_secs: 60,
                cert_cache_capacity: 8,
                ..HttpsMitmConfig::default()
            },
            dir.path(),
        )
        .unwrap_or_else(|e| panic!("{e}"));

        assert!(runtime.is_strict_host("api.openai.com"));
        assert!(!runtime.is_strict_host("example.com"));
    }

    #[test]
    fn ca_material_creates_key_and_cert_files() {
        let dir = tempdir().unwrap_or_else(|e| panic!("{e}"));
        let cfg = HttpsMitmConfig {
            enabled: true,
            intercept_hosts: vec!["api.openai.com".to_string()],
            cert_ttl_secs: 60,
            cert_cache_capacity: 8,
            ..HttpsMitmConfig::default()
        };

        let _ = HttpsMitmRuntime::new(cfg, dir.path()).unwrap_or_else(|e| panic!("{e}"));

        assert!(dir.path().join("firma-ca.crt").exists());
        assert!(dir.path().join("firma-ca.key").exists());
    }

    #[tokio::test]
    async fn cert_cache_reuses_issued_leafs() {
        let dir = tempdir().unwrap_or_else(|e| panic!("{e}"));
        let runtime = HttpsMitmRuntime::new(
            HttpsMitmConfig {
                enabled: true,
                intercept_hosts: vec!["api.openai.com".to_string()],
                cert_ttl_secs: 300,
                cert_cache_capacity: 8,
                ..HttpsMitmConfig::default()
            },
            dir.path(),
        )
        .unwrap_or_else(|e| panic!("{e}"));

        let _ = runtime
            .tls_acceptor_for_host("api.openai.com")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let _ = runtime
            .tls_acceptor_for_host("api.openai.com")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(runtime.cache_len_for_tests().await, 1);
    }
}
