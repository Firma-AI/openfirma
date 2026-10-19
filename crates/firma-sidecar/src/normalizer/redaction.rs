//! Shared query-name redaction for envelopes and audit diagnostic fragments.

pub(super) const DEFAULT_SENSITIVE_QUERY_PARAMS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "key",
    "token",
    "access_token",
    "access-token",
    "refresh_token",
    "auth",
    "password",
    "passwd",
    "pwd",
    "secret",
    "signature",
    "sig",
    "sas",
    "bearer",
    "authorization",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
];

pub fn redact_default_query_params(value: &str) -> String {
    redact_query_params(value, DEFAULT_SENSITIVE_QUERY_PARAMS)
}

/// Scan the whole diagnostic, not just an exact request-path substring.
/// Values are conservatively removed through the next query-pair delimiter.
pub(super) fn redact_query_params(value: &str, sensitive_params: &[impl AsRef<str>]) -> String {
    let mut result = String::with_capacity(value.len());
    let mut copied_until = 0;
    let mut scan_from = 0;
    while let Some(relative_eq) = value[scan_from..].find('=') {
        let eq = scan_from + relative_eq;
        // Never rescan a growing value prefix: candidates between equals signs
        // are disjoint, even for adversarial values containing many '=' bytes.
        let key_start = value[scan_from..eq]
            .rfind('&')
            .map_or(scan_from, |pos| scan_from + pos + 1);
        if !is_sensitive_query_key(&value[key_start..eq], sensitive_params) {
            scan_from = eq + 1;
            continue;
        }
        let value_start = eq + 1;
        let value_end = value[value_start..]
            .find('&')
            .map_or(value.len(), |pos| value_start + pos);
        result.push_str(&value[copied_until..value_start]);
        result.push_str("[REDACTED]");
        copied_until = value_end;
        scan_from = value_end;
    }
    result.push_str(&value[copied_until..]);
    result
}

fn is_sensitive_query_key(key: &str, sensitive_params: &[impl AsRef<str>]) -> bool {
    form_urlencoded::parse(key.as_bytes())
        .next()
        .is_some_and(|(decoded, _)| {
            sensitive_params.iter().any(|param| {
                let param = param.as_ref();
                if param.is_empty() || decoded.len() < param.len() {
                    return false;
                }
                let start = decoded.len() - param.len();
                decoded
                    .get(start..)
                    .is_some_and(|suffix| suffix.eq_ignore_ascii_case(param))
                    && (start == 0
                        || decoded[..start].chars().next_back().is_some_and(|c| {
                            matches!(c, '?' | '(' | '[' | '\'' | '"') || c.is_ascii_whitespace()
                        }))
            })
        })
}
