//! Load-time normalization of mapping-rule host patterns.

use firma_http::{Authority, HeaderMap, Method};
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};
use firma_sidecar::normalizer::MatchResult;
use firma_sidecar::pipeline::{ActionClassRegistry, IntentNormalizer, MappingTable, RawRequest};

fn rule(host: &str) -> MappingRuleConfig {
    MappingRuleConfig {
        method: Some(Method::GET),
        host: host.to_string(),
        path: Some("/repos/*".to_string()),
        action_class: "communication.external.read".to_string(),
    }
}

/// A rule host written with case or a trailing dot must still match runtime
/// hosts, which arrive lowercased with the trailing dot stripped; without
/// load-time normalization such a rule is dead.
#[test]
fn rule_hosts_are_normalized_at_load_time() -> anyhow::Result<()> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("API.GitHub.COM.")],
        },
        &ActionClassRegistry::v0_1(),
        false,
    )?;

    assert!(matches!(
        table.find_match(
            &Method::GET,
            &Authority::from_static("api.github.com"),
            "/repos/x"
        ),
        MatchResult::Matched(_)
    ));
    Ok(())
}

/// Default ports are stripped from rule hosts like runtime hosts, while a
/// nonstandard port is preserved and still matches ported traffic.
#[test]
fn rule_host_ports_mirror_runtime_normalization() -> anyhow::Result<()> {
    let registry = ActionClassRegistry::v0_1();
    let default_port = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.github.com:443")],
        },
        &registry,
        false,
    )?;
    assert!(matches!(
        default_port.find_match(
            &Method::GET,
            &Authority::from_static("api.github.com"),
            "/repos/x"
        ),
        MatchResult::Matched(_)
    ));

    let nonstandard_port = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.github.com:8443")],
        },
        &registry,
        false,
    )?;
    assert!(matches!(
        nonstandard_port.find_match(
            &Method::GET,
            &Authority::from_static("api.github.com:8443"),
            "/repos/x"
        ),
        MatchResult::Matched(_)
    ));
    assert!(matches!(
        nonstandard_port.find_match(
            &Method::GET,
            &Authority::from_static("api.github.com"),
            "/repos/x"
        ),
        MatchResult::NotProtected
    ));
    Ok(())
}

/// Default ports are stripped from bracketed IPv6 rule hosts exactly as they
/// are from IPv4/hostname rule hosts, while a nonstandard port is preserved
/// and still requires an exact port match.
#[test]
fn ipv6_rule_host_ports_mirror_runtime_normalization() -> anyhow::Result<()> {
    let registry = ActionClassRegistry::v0_1();
    let default_port = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("[::1]:443")],
        },
        &registry,
        false,
    )?;
    assert!(matches!(
        default_port.find_match(&Method::GET, &Authority::from_static("[::1]"), "/repos/x"),
        MatchResult::Matched(_)
    ));

    // A request host is normalized by the full pipeline before matching, so
    // it matches a default-port rule host whether or not it repeats the
    // port, exactly like an IPv4/hostname request.
    let normalizer = IntentNormalizer::new(default_port);
    for request_host in [
        Authority::from_static("[::1]"),
        Authority::from_static("[::1]:443"),
    ] {
        let envelope = normalizer
            .normalize(&RawRequest {
                method: Method::GET,
                host: request_host.clone(),
                path: "/repos/x".to_string(),
                headers: HeaderMap::new(),
                body: None,
                is_https: true,
            })
            .map_err(|decision| {
                anyhow::anyhow!("expected classification for {request_host}, got {decision:?}")
            })?;
        assert_eq!(
            envelope.intent().action_class,
            "communication.external.read"
        );
    }

    let nonstandard_port = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("[fe80::1]:8443")],
        },
        &registry,
        false,
    )?;
    assert!(matches!(
        nonstandard_port.find_match(
            &Method::GET,
            &Authority::from_static("[fe80::1]:8443"),
            "/repos/x"
        ),
        MatchResult::Matched(_)
    ));
    assert!(matches!(
        nonstandard_port.find_match(
            &Method::GET,
            &Authority::from_static("[fe80::1]"),
            "/repos/x"
        ),
        MatchResult::NotProtected
    ));
    Ok(())
}

/// A bracketed IPv6 literal preserves a nonstandard port on both sides of a
/// match, mirroring how a nonstandard port is preserved for IPv4/hostname
/// rule hosts.
#[test]
fn ipv6_rule_hosts_match_ipv6_request_hosts_on_any_port() -> anyhow::Result<()> {
    let registry = ActionClassRegistry::v0_1();
    for host in [
        Authority::from_static("[::1]:443"),
        Authority::from_static("[fe80::1]:8443"),
    ] {
        let table = MappingTable::from_config(
            &MappingRulesFile {
                rules: vec![rule(&host.to_string())],
            },
            &registry,
            false,
        )?;
        let normalizer = IntentNormalizer::new(table);

        let envelope = normalizer
            .normalize(&RawRequest {
                method: Method::GET,
                host: host.clone(),
                path: "/repos/x".to_string(),
                headers: HeaderMap::new(),
                body: None,
                is_https: true,
            })
            .map_err(|decision| {
                anyhow::anyhow!("expected classification for {host}, got {decision:?}")
            })?;

        assert_eq!(
            envelope.intent().action_class,
            "communication.external.read"
        );
    }
    Ok(())
}

/// An explicit port that is not the default for the request's scheme must be
/// preserved because the HTTP connector dispatches to the authority stored in
/// the normalized resource.
#[test]
fn ipv6_opposite_scheme_port_is_preserved_for_dispatch() -> anyhow::Result<()> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("[::1]:443")],
        },
        &ActionClassRegistry::v0_1(),
        false,
    )?;
    let normalizer = IntentNormalizer::new(table);

    let envelope = normalizer
        .normalize(&RawRequest {
            method: Method::GET,
            host: Authority::from_static("[::1]:443"),
            path: "/repos/x".to_string(),
            headers: HeaderMap::new(),
            body: None,
            // Key detail: not using HTTPS, so default port would be `80`
            is_https: false,
        })
        .map_err(|decision| anyhow::anyhow!("expected classification, got {decision:?}"))?;

    assert_eq!(
        envelope.intent().resource.get("host").map(String::as_str),
        Some("[::1]:443"),
        "HTTP dispatch must retain the explicitly requested port 443"
    );
    Ok(())
}

/// The same opposite-scheme-port preservation applies to IPv4/hostname
/// authorities, not just bracketed IPv6 literals: dispatch-host
/// normalization must not special-case address family.
#[test]
fn ipv4_opposite_scheme_port_is_preserved_for_dispatch() -> anyhow::Result<()> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.example.com:443")],
        },
        &ActionClassRegistry::v0_1(),
        false,
    )?;
    let normalizer = IntentNormalizer::new(table);

    let envelope = normalizer
        .normalize(&RawRequest {
            method: Method::GET,
            host: Authority::from_static("api.example.com:443"),
            path: "/repos/x".to_string(),
            headers: HeaderMap::new(),
            body: None,
            // Key detail: not using HTTPS, so default port would be `80`
            is_https: false,
        })
        .map_err(|decision| anyhow::anyhow!("expected classification, got {decision:?}"))?;

    assert_eq!(
        envelope.intent().resource.get("host").map(String::as_str),
        Some("api.example.com:443"),
        "HTTP dispatch must retain the explicitly requested port 443"
    );
    Ok(())
}

/// A trailing dot must not evade a host-scoped rule whether it hides before
/// the port (`host.:8443`) or after it (`host:443.`); every spelling of the
/// same authority normalizes identically. Exercised through the normalizer,
/// which owns request-host normalization.
#[test]
fn trailing_dots_around_ports_cannot_evade_rules() -> anyhow::Result<()> {
    for (rule_host, request_host) in [
        (
            "api.github.com:8443",
            Authority::from_static("API.GitHub.COM.:8443"),
        ),
        (
            "api.github.com",
            Authority::from_static("api.github.com:443."),
        ),
    ] {
        let table = MappingTable::from_config(
            &MappingRulesFile {
                rules: vec![rule(rule_host)],
            },
            &ActionClassRegistry::v0_1(),
            false,
        )?;
        let normalizer = IntentNormalizer::new(table);

        let envelope = normalizer
            .normalize(&RawRequest {
                method: Method::GET,
                host: request_host.clone(),
                path: "/repos/x".to_string(),
                headers: HeaderMap::new(),
                body: None,
                is_https: true,
            })
            .map_err(|decision| {
                anyhow::anyhow!("expected classification for {request_host}, got {decision:?}")
            })?;

        assert_eq!(
            envelope.intent().action_class,
            "communication.external.read"
        );
    }
    Ok(())
}

/// Degenerate hosts that would silently normalize into the bare catch-all
/// or into an unmatchable empty name are rejected at validation.
#[test]
fn degenerate_catch_all_host_patterns_are_rejected() {
    for host in [
        "*.", "*:443", "*.:443", "*..:80", "*.:8443", ".", ":443", ":8080",
    ] {
        let result = MappingTable::from_config(
            &MappingRulesFile {
                rules: vec![rule(host)],
            },
            &ActionClassRegistry::v0_1(),
            false,
        );
        assert!(result.is_err(), "{host} must be rejected at validation");
    }
}

/// A literal `*` name with a nonstandard port is a legitimate port-scoped
/// catch-all: it loads and matches every host on that port, and only that
/// port.
#[test]
fn explicit_port_scoped_catch_all_still_loads_and_matches() -> anyhow::Result<()> {
    let table = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![MappingRuleConfig {
                method: Some(Method::GET),
                host: "*:8443".to_string(),
                path: None,
                action_class: "communication.external.read".to_string(),
            }],
        },
        &ActionClassRegistry::v0_1(),
        false,
    )?;

    assert!(matches!(
        table.find_match(
            &Method::GET,
            &Authority::from_static("anything.example:8443"),
            "/x"
        ),
        MatchResult::Matched(_)
    ));
    assert!(matches!(
        table.find_match(
            &Method::GET,
            &Authority::from_static("anything.example"),
            "/x"
        ),
        MatchResult::NotProtected
    ));
    Ok(())
}

/// Case or trailing-dot variants of the same rule are the same rule; the
/// duplicate check compares normalized hosts so they fail at startup.
#[test]
fn duplicate_detection_compares_normalized_hosts() {
    let result = MappingTable::from_config(
        &MappingRulesFile {
            rules: vec![rule("api.github.com"), rule("API.GITHUB.COM.")],
        },
        &ActionClassRegistry::v0_1(),
        false,
    );

    assert!(result.is_err());
}
