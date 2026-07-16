//! Intercept transform for a vault CLI's captured output.
//!
//! Runs the policy's [`firma_core::SecretMatcher`] over the plaintext output to
//! extract the secrets into the firma-run dictionary and rewrite the output so
//! the agent only ever sees placeholders.
//!
//! The matcher itself (JSONPath / regex) is compiled and executed by
//! [`firma_sidecar::secret_matcher`]; this module owns the mint + store
//! orchestration. It is the producer half of the secret machinery (the consumer
//! is redaction rehydration). See `docs/architecture/secrets-interception.md`.

use firma_core::SecretMatcher;
use firma_sidecar::secret_matcher::{CompiledMatcher, MatcherError};

use super::{Placeholder, SecretStore, SecretStoreError, SecretValue};

/// Errors from applying an intercept transform.
///
/// On any error the broker must **not** forward the raw output (it still
/// contains the plaintext secret) — it fails closed instead.
#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    /// The matcher failed to compile or execute.
    #[error(transparent)]
    Matcher(#[from] MatcherError),
    /// A minted secret could not be stored.
    #[error(transparent)]
    Store(#[from] SecretStoreError),
}

/// Extract secrets from a vault CLI's `output` and rewrite it with placeholders.
///
/// Each secret found by `matcher` is stored under a placeholder minted from
/// `placeholder_template`; the returned bytes have every secret value replaced
/// by its placeholder.
///
/// # Errors
///
/// Returns [`InterceptError`] if the matcher fails to compile or execute, or a
/// minted secret cannot be stored.
pub fn intercept(
    matcher: &SecretMatcher,
    output: &[u8],
    placeholder_template: &str,
    store: &mut SecretStore,
) -> Result<Vec<u8>, InterceptError> {
    let compiled = CompiledMatcher::compile(matcher)?;

    // The mint callback cannot return an error, so a store failure is stashed
    // here and surfaced after the rewrite (fail-closed).
    let mut store_error: Option<SecretStoreError> = None;
    let rewritten = compiled.rewrite(output, &mut |name, value| {
        let placeholder = Placeholder::from_template(placeholder_template, name);
        if let Err(error) = store.insert(placeholder.clone(), SecretValue::from(value)) {
            store_error = Some(error);
        }
        placeholder.as_str().to_owned()
    })?;

    if let Some(error) = store_error {
        return Err(InterceptError::Store(error));
    }
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
        }
    }

    #[test]
    fn json_matcher_rewrites_each_secret_and_stores() {
        let mut store = SecretStore::new();
        let output = json!([
            { "key": "db_password", "value": "s3cr3t" },
            { "key": "api_key", "value": "AAA" },
        ])
        .to_string();

        let rewritten =
            intercept(&json_matcher(), output.as_bytes(), TEMPLATE, &mut store).unwrap();
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
            store.resolve("firma-secret://bitwarden/db_password"),
            Some(&b"s3cr3t"[..])
        );
        assert_eq!(store.mask_matches(b"echo s3cr3t").count(), 1);
    }

    #[test]
    fn regex_matcher_rewrites_env_style_values() {
        let mut store = SecretStore::new();
        let matcher = SecretMatcher::Regex {
            pattern: r"(?m)^(?P<name>[^=]+)=(?P<value>.+)$".to_string(),
        };

        let rewritten = intercept(
            &matcher,
            b"DB=s3cr3t\nAPI=AAA\n",
            "firma-secret://env/{name}",
            &mut store,
        )
        .unwrap();

        assert_eq!(
            rewritten,
            b"DB=firma-secret://env/DB\nAPI=firma-secret://env/API\n"
        );
        assert_eq!(store.resolve("firma-secret://env/DB"), Some(&b"s3cr3t"[..]));
    }

    #[test]
    fn invalid_json_is_rejected() {
        let mut store = SecretStore::new();
        let error = intercept(&json_matcher(), b"not json", TEMPLATE, &mut store).unwrap_err();
        assert!(matches!(
            error,
            InterceptError::Matcher(MatcherError::Json(_))
        ));
        assert!(store.is_empty());
    }
}
