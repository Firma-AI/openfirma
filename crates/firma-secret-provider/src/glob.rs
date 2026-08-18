//! Simple glob matching shared by mapping-rule host/path matching
//! (`firma-sidecar`'s normalizer) and secret-provider host/path matching
//! (this crate's [`crate::spec::http::HttpIntegrationSpec`]) — one
//! implementation so the two never silently diverge.

/// Simple glob matching where `*` matches any sequence of characters.
///
/// The wildcard crosses separators: `*.example.com` matches both
/// `api.example.com` and `deep.api.example.com`, and a bare `*` matches
/// everything.
///
/// - `/v1/*/completions` matches `/v1/chat/completions`
#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Split into segments by the `*` wildcard
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcard — exact match
        return pattern == value;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(found) => {
                // First part must match at the start
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }

    // Last part must match at the end
    if let Some(last) = parts.last()
        && !last.is_empty()
    {
        return value.ends_with(last);
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("api.openai.com", "api.openai.com"));
        assert!(!glob_match("api.openai.com", "api.anthropic.com"));
    }

    #[test]
    fn glob_match_wildcard_prefix() {
        assert!(glob_match("*.openai.com", "api.openai.com"));
        assert!(!glob_match("*.openai.com", "api.anthropic.com"));
    }

    #[test]
    fn glob_match_star_matches_all() {
        assert!(glob_match("*", "anything.at.all"));
    }

    #[test]
    fn glob_match_path_wildcard() {
        assert!(glob_match("/v1/*/completions", "/v1/chat/completions"));
        assert!(!glob_match("/v1/*/completions", "/v2/chat/completions"));
    }
}
