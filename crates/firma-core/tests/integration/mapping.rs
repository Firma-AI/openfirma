use std::collections::{BTreeSet, HashSet, VecDeque};

use firma_core::{
    glob_match, glob_patterns_overlap, mapping_specificity, normalize_mapping_host,
    split_mapping_authority,
};

#[test]
fn glob_matching_preserves_mapping_wildcard_semantics() {
    assert!(glob_match("api*.example.com", "api.example.com"));
    assert!(glob_match("*.example.com", "deep.api.example.com"));
    assert!(glob_match("/v1/*/messages", "/v1/accounts/42/messages"));
    assert!(!glob_match("*.example.com", "example.com"));
    assert!(!glob_match("api?.example.com", "api1.example.com"));
}

#[test]
fn mapping_host_normalization_preserves_observed_forms() {
    let cases = [
        (" API.Example.COM. ", "api.example.com"),
        ("api.example.com.:8443", "api.example.com:8443"),
        ("api.example.com:80", "api.example.com"),
        ("api.example.com:443.", "api.example.com"),
        ("[FE80::1]:443", "[fe80::1]"),
        ("[FE80::1]:8443", "[fe80::1]:8443"),
        ("example.com:https", "example.com:https"),
    ];

    for (input, expected) in cases {
        assert_eq!(normalize_mapping_host(input), expected);
    }
}

#[test]
fn mapping_ports_canonicalize_numeric_forms() {
    let cases = [
        ("example.com:001", "example.com:1"),
        ("example.com:00080", "example.com"),
        ("example.com:00443", "example.com"),
        ("example.com:08443", "example.com:8443"),
        ("[::1]:00443", "[::1]"),
        ("[fe80::1]:08443", "[fe80::1]:8443"),
    ];

    for (input, expected) in cases {
        assert_eq!(normalize_mapping_host(input), expected, "{input}");
    }
    assert_eq!(
        split_mapping_authority("example.com:001"),
        ("example.com".to_owned(), Some("1".to_owned()))
    );
}

#[test]
fn authority_splitting_supports_both_families() {
    assert_eq!(
        split_mapping_authority("API.Example.COM.:8443"),
        ("api.example.com".to_owned(), Some("8443".to_owned()))
    );
    assert_eq!(
        split_mapping_authority("[FE80::1]:443"),
        ("[fe80::1]".to_owned(), Some("443".to_owned()))
    );
    assert_eq!(
        split_mapping_authority("  example.com:80  "),
        ("example.com".to_owned(), Some("80".to_owned()))
    );
    // A non-numeric suffix is part of the name, never a port.
    assert_eq!(
        split_mapping_authority("example.com:https"),
        ("example.com:https".to_owned(), None)
    );
    // An unbracketed IPv6 literal keeps its colons in the name instead of
    // being misparsed as a host-plus-port pair.
    assert_eq!(split_mapping_authority("::1"), ("::1".to_owned(), None));
}

#[test]
fn specificity_remains_additive() {
    assert_eq!(mapping_specificity(false, "example.com", None), 100);
    assert_eq!(mapping_specificity(true, "*.example.com", None), 10);
    assert_eq!(
        mapping_specificity(true, "*.example.com", Some("/v1/accounts/*")),
        18
    );
    assert_eq!(
        mapping_specificity(true, "*.example.com", Some("/v1/accounts/42")),
        28
    );
}

#[test]
fn overlap_matches_agreed_sentinels_in_both_directions() {
    let cases = [
        ("example.com", "EXAMPLE.COM.:443", true),
        ("*.example.com", "api.example.com", true),
        ("*.example.com", "example.com", false),
        ("*", "api.example.com", true),
        ("*.example.com", "api.example.org", false),
        ("api*.example.com", "*prod.example.com", true),
        (
            "copilot-reports-*.b01.azurefd.net",
            "copilot-reports-team.b01.azurefd.net",
            true,
        ),
        ("api.*.example.com", "api.example.com", false),
        ("example.com:80", "EXAMPLE.COM.:443", true),
        ("example.com:8443", "example.com:9443", false),
        ("127.0.0.1", "127.0.0.1:443", true),
        ("[::1]", "[::1]:80", true),
    ];

    for (left, right, expected) in cases {
        let left = normalize_mapping_host(left);
        let right = normalize_mapping_host(right);
        assert_eq!(glob_patterns_overlap(&left, &right), expected);
        assert_eq!(glob_patterns_overlap(&right, &left), expected);
    }
}

#[test]
fn overlap_matches_an_independent_reference_automaton() {
    let patterns = generated_patterns(4);

    for left in &patterns {
        for right in &patterns {
            assert_eq!(
                glob_patterns_overlap(left, right),
                reference_overlap(left, right),
                "left={left:?}, right={right:?}"
            );
        }
    }
}

fn generated_patterns(max_length: usize) -> Vec<String> {
    let mut patterns = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..max_length {
        let mut next = Vec::new();
        for prefix in frontier {
            for token in ['a', 'b', '*'] {
                let mut pattern = prefix.clone();
                pattern.push(token);
                patterns.push(pattern.clone());
                next.push(pattern);
            }
        }
        frontier = next;
    }
    patterns
}

fn reference_overlap(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let alphabet = left
        .iter()
        .chain(right)
        .copied()
        .filter(|token| *token != b'*')
        .chain(*b"\0")
        .collect::<BTreeSet<_>>();
    let start = (epsilon_closure(left, [0]), epsilon_closure(right, [0]));
    let mut pending = VecDeque::from([start]);
    let mut visited = HashSet::new();

    while let Some((left_states, right_states)) = pending.pop_front() {
        if !visited.insert((left_states.clone(), right_states.clone())) {
            continue;
        }
        if left_states.contains(&left.len()) && right_states.contains(&right.len()) {
            return true;
        }
        for token in &alphabet {
            let next_left = reference_step(left, &left_states, *token);
            let next_right = reference_step(right, &right_states, *token);
            if !next_left.is_empty() && !next_right.is_empty() {
                pending.push_back((next_left, next_right));
            }
        }
    }

    false
}

fn epsilon_closure(pattern: &[u8], states: impl IntoIterator<Item = usize>) -> BTreeSet<usize> {
    let mut closure = states.into_iter().collect::<BTreeSet<_>>();
    let mut pending = closure.iter().copied().collect::<Vec<_>>();
    while let Some(state) = pending.pop() {
        if pattern.get(state) == Some(&b'*') && closure.insert(state + 1) {
            pending.push(state + 1);
        }
    }
    closure
}

fn reference_step(pattern: &[u8], states: &BTreeSet<usize>, token: u8) -> BTreeSet<usize> {
    let destinations = states.iter().filter_map(|state| match pattern.get(*state) {
        Some(b'*') => Some(*state),
        Some(literal) if *literal == token => Some(*state + 1),
        _ => None,
    });
    epsilon_closure(pattern, destinations)
}
