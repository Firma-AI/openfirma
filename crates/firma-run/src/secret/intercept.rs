//! Intercept transform for a vault CLI's captured output.
//!
//! Runs the policy's [`firma_core::SecretMatcher`] over the plaintext output to
//! extract the secrets into the firma-run dictionary and rewrite the output so
//! the agent only ever sees placeholders.
//!
//! The matcher itself (JSONPath / regex) is compiled and executed by
//! [`firma_secret_provider`]; this module owns the mint + store
//! orchestration. It is the producer half of the secret machinery (the consumer
//! is redaction rehydration). See `docs/architecture/secrets-interception.md`.

use arc_swap::ArcSwap;
use firma_core::SecretMatcher;
use firma_secret_provider::{CompiledMatcher, MatcherError};

use super::{Placeholder, SecretStore, SecretValue};

/// Errors from applying an intercept transform.
///
/// On any error the broker must **not** forward the raw output (it still
/// contains the plaintext secret) — it fails closed instead.
#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    /// The matcher failed to compile or execute.
    #[error(transparent)]
    Matcher(#[from] MatcherError),
}

/// Extract secrets from a vault CLI's `output` and rewrite it with placeholders.
///
/// Each secret found by `matcher` is stored in `store` under a placeholder
/// minted from `placeholder_template`. When the matcher's `domain_path` selects
/// a hostname for the item, the secret is scoped to that host; otherwise it
/// resolves for any host.
///
/// # Errors
///
/// Returns [`InterceptError`] if the matcher fails to compile or execute.
pub fn intercept(
    matcher: &SecretMatcher,
    output: &[u8],
    placeholder_template: &str,
    store: &ArcSwap<SecretStore>,
) -> Result<Vec<u8>, InterceptError> {
    let compiled = CompiledMatcher::compile(matcher)?;

    let rewritten = compiled.rewrite(output, &mut |name, value, domain, item| {
        let placeholder = Placeholder::from_template(placeholder_template, item, name);
        let domain = domain.map(str::to_owned);
        store.rcu(|store| {
            let mut store = SecretStore::clone(store);
            store.insert(
                placeholder.clone(),
                domain.clone(),
                SecretValue::from(value),
            );
            store
        });
        placeholder.as_str().to_owned()
    })?;

    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const TEMPLATE: &str = "firma-secret://bitwarden/{name}";

    fn json_matcher() -> SecretMatcher {
        SecretMatcher::Json {
            value_path: "$[*].value".to_string(),
            name_path: "$[*].key".to_string(),
            item_path: None,
            domain_path: None,
            domain_is_url: false,
        }
    }

    fn json_matcher_with_domain() -> SecretMatcher {
        SecretMatcher::Json {
            value_path: "$[*].value".to_string(),
            name_path: "$[*].key".to_string(),
            item_path: None,
            domain_path: Some("$[*].domain".to_string()),
            domain_is_url: false,
        }
    }

    #[test]
    fn json_matcher_rewrites_each_secret_and_stores() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let output = json!([
            { "key": "db_password", "value": "s3cr3t" },
            { "key": "api_key", "value": "AAA" },
        ])
        .to_string();

        let rewritten = intercept(&json_matcher(), output.as_bytes(), TEMPLATE, &store).unwrap();
        let rewritten: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            rewritten[0]["value"],
            json!("firma-secret://bitwarden/db_password")
        );
        assert_eq!(
            rewritten[1]["value"],
            json!("firma-secret://bitwarden/api_key")
        );
        assert_eq!(
            store
                .load()
                .resolve("firma-secret://bitwarden/db_password", "any.domain"),
            Some(&b"s3cr3t"[..])
        );
    }

    #[test]
    fn regex_matcher_rewrites_env_style_values() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let matcher = SecretMatcher::Regex {
            pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$".to_string(),
            domain_is_url: false,
        };

        let rewritten = intercept(
            &matcher,
            b"DB=s3cr3t\nAPI=AAA\n",
            "firma-secret://env/{name}",
            &store,
        )
        .unwrap();

        assert_eq!(
            rewritten,
            b"DB=firma-secret://env/DB\nAPI=firma-secret://env/API\n"
        );
        assert_eq!(
            store.load().resolve("firma-secret://env/DB", "any.domain"),
            Some(&b"s3cr3t"[..])
        );
    }

    #[test]
    fn domain_path_scopes_secret_to_extracted_host() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let output = json!([
            { "key": "github-token", "value": "ghp_abc", "domain": "api.github.com" },
        ])
        .to_string();

        intercept(
            &json_matcher_with_domain(),
            output.as_bytes(),
            TEMPLATE,
            &store,
        )
        .unwrap();

        assert_eq!(
            store
                .load()
                .resolve("firma-secret://bitwarden/github-token", "api.github.com"),
            Some(&b"ghp_abc"[..]),
            "should resolve for matching domain"
        );
        assert_eq!(
            store
                .load()
                .resolve("firma-secret://bitwarden/github-token", "api.stripe.com"),
            None,
            "should not resolve for wrong domain"
        );
    }

    #[test]
    fn invalid_json_is_rejected() {
        let store = ArcSwap::from_pointee(SecretStore::new());
        let error = intercept(&json_matcher(), b"not json", TEMPLATE, &store).unwrap_err();
        assert!(matches!(
            error,
            InterceptError::Matcher(MatcherError::Json(_))
        ));
        assert!(store.load().is_empty());
    }
}
