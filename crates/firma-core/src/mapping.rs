//! Shared action-mapping matching and ordering semantics.

use std::collections::{HashSet, VecDeque};

/// A canonical snapshot rule violates the shared mapping language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagedMappingRuleError {
    #[error("invalid normalized host")]
    Host,
    #[error("invalid HTTP method")]
    Method,
    #[error("invalid path")]
    Path,
    #[error("unknown action class")]
    ActionClass,
}

/// Validate the canonical rule language shared by snapshot producers and consumers.
///
/// # Errors
/// Rejects non-canonical hosts, unsupported methods, empty/oversized/NUL paths,
/// and action classes outside the built-in registry.
pub fn validate_managed_rule(
    method: Option<&str>,
    host: &str,
    path: Option<&str>,
    action_class: &str,
) -> Result<(), ManagedMappingRuleError> {
    if !mapping_host_is_canonical(host) {
        return Err(ManagedMappingRuleError::Host);
    }
    if method.is_some_and(|method| method.parse::<crate::HttpMethod>().is_err()) {
        return Err(ManagedMappingRuleError::Method);
    }
    if path.is_some_and(|path| path.is_empty() || path.len() > 4096 || path.contains('\0')) {
        return Err(ManagedMappingRuleError::Path);
    }
    if action_class.parse::<crate::ActionClass>().is_err() {
        return Err(ManagedMappingRuleError::ActionClass);
    }
    Ok(())
}

/// Check authored authority spelling before normalization can erase intent.
///
/// # Errors
/// Rejects malformed authorities, empty host names, and implicit promotion to
/// a catch-all. Canonical snapshot validation additionally checks DNS and ports.
pub fn validate_authored_mapping_host(host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    let malformed = host.strip_prefix('[').map_or_else(
        || host.contains(['[', ']']) || host.matches(':').count() > 1,
        |bracketed| {
            bracketed.split_once(']').is_none_or(|(name, suffix)| {
                name.is_empty()
                    || name.contains(['[', ']'])
                    || (!name.contains(':') && !name.contains('*'))
                    || (!suffix.is_empty()
                        && suffix
                            .strip_prefix(':')
                            .is_none_or(|port| port.is_empty() || port.contains([':', '[', ']'])))
            })
        },
    );
    if malformed {
        return Err(format!(
            "host pattern '{host}' is not a valid authority; use at most one port suffix and bracket IPv6 literals"
        ));
    }
    let normalized = normalize_mapping_host(host);
    if normalized.is_empty() || normalized.starts_with(':') {
        return Err(format!(
            "host pattern '{host}' normalizes to a host with an empty name and can never match"
        ));
    }
    if normalized == "*" && host != "*" {
        return Err(format!(
            "host pattern '{host}' would normalize to the bare catch-all '*'; write '*' explicitly if that is intended"
        ));
    }
    let normalized_name = match normalized.rsplit_once(':') {
        Some((name, port)) if is_valid_port(port) => name,
        _ => normalized.as_str(),
    };
    let written = host.trim_end_matches('.');
    let written_name = match written.rsplit_once(':') {
        Some((name, port)) if is_valid_port(port) => name,
        _ => written,
    };
    if normalized_name == "*" && written_name != "*" {
        return Err(format!(
            "host pattern '{host}' would normalize its name to the catch-all '*'; write the '*' explicitly if that is intended"
        ));
    }
    Ok(())
}

/// Whether a mapping host is canonical and valid for an enforcement snapshot.
///
/// Snapshots use lowercase DNS patterns, bracketed IPv6 literals, and optional
/// non-default numeric ports or explicit digit/`*` port patterns. Authored files must validate their spelling before
/// normalization so that normalization cannot silently promote a catch-all.
#[must_use]
fn mapping_host_is_canonical(host: &str) -> bool {
    if host.is_empty() || normalize_mapping_host(host) != host {
        return false;
    }
    if let Some((name, port)) = host.rsplit_once(':')
        && port.contains('*')
    {
        return port.len() <= 5
            && port
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'*')
            && (!name.contains(':') || (name.starts_with('[') && name.ends_with(']')))
            && mapping_host_is_canonical(name);
    }
    let (name, port) = split_mapping_authority(host);
    if port.is_some_and(|port| port.parse::<u16>().map_or(true, |port| port == 0)) {
        return false;
    }
    if name == "*" {
        return true;
    }
    if let Some(address) = name
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
    {
        return address.parse::<std::net::Ipv6Addr>().is_ok();
    }
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'*'))
        })
}

/// Matches `value` against a pattern where `*` accepts any character sequence.
///
/// Wildcards cross host labels and path segments. No other character has
/// special meaning.
#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut reachable = vec![false; value.len() + 1];
    reachable[0] = true;

    for token in pattern {
        if *token == b'*' {
            let mut seen = false;
            for position in &mut reachable {
                seen |= *position;
                *position = seen;
            }
        } else {
            for index in (1..=value.len()).rev() {
                reachable[index] = reachable[index - 1] && value[index - 1] == *token;
            }
            reachable[0] = false;
        }
    }

    reachable[value.len()]
}

/// Returns whether two `*` glob patterns accept at least one common string.
#[must_use]
pub fn glob_patterns_overlap(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut pending = VecDeque::from([(0usize, 0usize)]);
    let mut visited = HashSet::new();

    while let Some((left_index, right_index)) = pending.pop_front() {
        if !visited.insert((left_index, right_index)) {
            continue;
        }
        if left_index == left.len() && right_index == right.len() {
            return true;
        }

        let left_token = left.get(left_index).copied();
        let right_token = right.get(right_index).copied();

        if left_token == Some(b'*') {
            pending.push_back((left_index + 1, right_index));
        }
        if right_token == Some(b'*') {
            pending.push_back((left_index, right_index + 1));
        }

        match (left_token, right_token) {
            (Some(b'*'), Some(b'*')) => pending.push_back((left_index, right_index)),
            (Some(b'*'), Some(_)) => pending.push_back((left_index, right_index + 1)),
            (Some(_), Some(b'*')) => pending.push_back((left_index + 1, right_index)),
            (Some(left), Some(right)) if left == right => {
                pending.push_back((left_index + 1, right_index + 1));
            }
            _ => {}
        }
    }

    false
}

/// Splits a mapping authority into its canonical name and optional port.
///
/// This is the single authority splitter shared by host normalization,
/// dispatch-host normalization, and the managed mapping domain types, so the
/// three can never disagree on what a spelling means. The input is trimmed;
/// DNS names are lowercased with trailing dots removed; only an all-digit
/// trailing segment after the last `:` (or after `]:` for bracketed IPv6)
/// counts as a port. Anything else (for example `example.com:https` or an
/// unbracketed IPv6 literal) is returned whole as the name with no port.
///
/// Intentionally not built on `std::net` parsers: this layer splits and
/// preserves spelling over a pattern language that includes `*` wildcards,
/// which no std parser accepts, while validation lives downstream in the
/// domain types. Parsing first would either reject wildcards or re-render
/// canonically, both of which change the observable normalization contract
/// pinned by the mapping compatibility corpus.
#[must_use]
pub fn split_mapping_authority(authority: &str) -> (String, Option<String>) {
    let trimmed = authority.trim();
    if trimmed.starts_with('[') {
        split_ipv6_authority(trimmed)
    } else {
        split_authority(trimmed)
    }
}

/// Normalizes a mapping host pattern into `OpenFirma`'s canonical matching form.
///
/// Normalization trims whitespace, lowercases ASCII host text, removes DNS
/// trailing dots, removes ports 80 and 443, and preserves other numeric ports.
#[must_use]
pub fn normalize_mapping_host(host: &str) -> String {
    let (name, port) = split_mapping_authority(host);
    match port.as_deref() {
        Some("443" | "80") | None => name,
        Some(port) => format!("{name}:{port}"),
    }
}

/// Computes `OpenFirma`'s additive mapping-rule specificity score.
#[must_use]
pub fn mapping_specificity(
    has_method: bool,
    host_pattern: &str,
    path_pattern: Option<&str>,
) -> usize {
    let mut score = usize::from(!host_pattern.contains('*')) * 100;
    score += usize::from(has_method) * 10;

    if let Some(path) = path_pattern {
        score += 5;
        score += path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .count();
        score += usize::from(!path.contains('*')) * 10;
    }

    score
}

fn is_valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

/// Canonicalizes an all-digit port by stripping leading zeros (`001` → `1`).
///
/// Digit strings that exceed `u32` are returned unchanged; the domain
/// validator rejects out-of-range ports downstream. Canonicalizing here
/// keeps duplicate detection and runtime matching consistent for every
/// consumer of [`split_mapping_authority`].
fn canonical_port(port: &str) -> String {
    port.parse::<u32>()
        .map_or_else(|_| port.to_owned(), |number| number.to_string())
}

/// Splits a hostname/IPv4 authority into a lowercased name and an optional
/// port.
///
/// Trailing dots are stripped both before the port split (`host:443.`) and
/// from the name part after it (`host.:443`); either position spells the
/// same authority (RFC 4343 case-insensitivity plus the FQDN trailing dot).
/// Wildcards pass through untouched except for this dot handling (`*.:443`
/// splits to name `*`, which validation rejects as a silent catch-all
/// promotion). A name containing `:` is an unbracketed IPv6 literal, never a
/// host-plus-port pair, so it is returned whole.
fn split_authority(host: &str) -> (String, Option<String>) {
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    let (name, port) = match lower.rsplit_once(':') {
        Some((name, port)) if !name.is_empty() && !name.contains(':') && is_valid_port(port) => {
            (name, Some(port))
        }
        _ => (lower.as_str(), None),
    };
    (
        name.trim_end_matches('.').to_string(),
        port.map(canonical_port),
    )
}

/// Splits a bracketed IPv6 authority into a lowercased, bracketed name and
/// an optional port.
///
/// The port is split at the closing bracket rather than the last colon,
/// since an IPv6 address itself contains colons. Input without brackets is
/// never treated as IPv6 here, so an unbracketed literal such as `::1` keeps
/// its colons in the name and fails DNS validation downstream instead of
/// being misparsed as a host-plus-port pair.
fn split_ipv6_authority(host: &str) -> (String, Option<String>) {
    let lower = host.to_ascii_lowercase();
    match lower.split_once("]:") {
        Some((name, port)) if is_valid_port(port) => {
            (format!("{name}]"), Some(canonical_port(port)))
        }
        _ => (lower, None),
    }
}
