use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher, SecretNameSource};
use firma_secret_provider::{CompiledMatcher, MatcherError, SecretPlaceholder};
use secrecy::ExposeSecret;

pub fn selector(path: &str, scope: SecretJsonSelectorScope) -> SecretJsonSelector {
    SecretJsonSelector {
        path: path.to_owned(),
        scope,
    }
}

pub fn json(record_path: &str, value_path: &str, name_path: &str) -> SecretMatcher {
    SecretMatcher::Json {
        record_path: record_path.to_owned(),
        value_path: value_path.to_owned(),
        name: SecretNameSource::Path {
            path: name_path.to_owned(),
        },
        item_selector: None,
        domain_selector: None,
    }
}

pub fn json_record_key_name(record_path: &str, value_path: &str) -> SecretMatcher {
    SecretMatcher::Json {
        record_path: record_path.to_owned(),
        value_path: value_path.to_owned(),
        name: SecretNameSource::RecordKey,
        item_selector: None,
        domain_selector: None,
    }
}

pub fn json_with_metadata(
    record_path: &str,
    value_path: &str,
    name_path: &str,
    item_selector: Option<SecretJsonSelector>,
    domain_selector: Option<SecretJsonSelector>,
) -> SecretMatcher {
    SecretMatcher::Json {
        record_path: record_path.to_owned(),
        value_path: value_path.to_owned(),
        name: SecretNameSource::Path {
            path: name_path.to_owned(),
        },
        item_selector,
        domain_selector,
    }
}

pub fn regex(pattern: &str) -> SecretMatcher {
    SecretMatcher::Regex {
        pattern: pattern.to_owned(),
    }
}

/// One extracted `(name, value)` pair, along with the domain(s)/item
/// metadata a matcher may attach, captured by [`rewrite_mint_placeholders`].
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub value: String,
    pub domains: Vec<String>,
    pub item: Option<String>,
}

/// Runs `matcher` against `output`, collecting every extracted entry and
/// returning it alongside the rewritten output. Mints real randomized
/// [`SecretPlaceholder`] tokens (rather than a fixed sentinel) so callers can
/// exercise the rewritten output as it would actually look in production
/// (e.g. for insta snapshots that redact the random suffix).
///
/// # Errors
///
/// Returns whatever [`CompiledMatcher::rewrite`] returns for mismatched input.
pub fn rewrite_mint_placeholders(
    matcher: &CompiledMatcher,
    output: &[u8],
) -> Result<(Vec<u8>, Vec<Entry>), MatcherError> {
    let mut entries = Vec::new();
    let out = matcher.rewrite(output, &mut |name, value, domains, item| {
        entries.push(Entry {
            name,
            value: value.expose_secret().to_owned(),
            domains: domains
                .iter()
                .map(|authority| authority.as_str().to_owned())
                .collect(),
            item,
        });
        SecretPlaceholder::new()
    })?;
    Ok((out, entries))
}
