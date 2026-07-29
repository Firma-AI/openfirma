use firma_core::{SecretJsonSelector, SecretJsonSelectorScope, SecretMatcher};

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
        name_path: name_path.to_owned(),
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
        name_path: name_path.to_owned(),
        item_selector,
        domain_selector,
    }
}

pub fn regex(pattern: &str) -> SecretMatcher {
    SecretMatcher::Regex {
        pattern: pattern.to_owned(),
    }
}
