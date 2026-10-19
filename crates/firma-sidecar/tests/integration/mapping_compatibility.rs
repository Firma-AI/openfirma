//! Compatibility runner for the shared mapping corpus.
//!
//! Observed cases execute the Sidecar's public parser, validator, mapping
//! table, and intent normalizer APIs. The Sidecar has no managed mapping-set
//! owner type yet, so agreed owner decomposition and overlap are checked here
//! by test-only decomposition/recomposition logic over the shared production
//! host and glob primitives.

#![expect(
    clippy::panic,
    reason = "corpus runner panics include the stable case ID and actual outcome"
)]

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use firma_core::{
    ActionClass, glob_patterns_overlap, normalize_mapping_host, split_mapping_authority,
};
use firma_http::{Authority, HeaderMap, Method};
use firma_sidecar::config::MappingRulesFile;
use firma_sidecar::normalizer::MatchResult;
use firma_sidecar::pipeline::{
    ActionClassRegistry, EnforcementDecision, IntentNormalizer, MappingTable, RawRequest,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../../compatibility/mapping/cases.toml");
const SUPPORTED_CORPUS_SCHEMA: u32 = 1;
const OBSERVED_REVISION: &str = "a737ed612b8f16019f1cf3e58012af6d512bba50";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: u32,
    observed_revision: String,
    observed_methods: ObservedMethods,
    observed_action_classes: ObservedActionClasses,
    catalog_summary: CatalogSummary,
    parse_cases: Vec<ParseCase>,
    validation_cases: Vec<ValidationCase>,
    host_normalization_cases: Vec<HostNormalizationCase>,
    path_normalization_cases: Vec<PathNormalizationCase>,
    glob_cases: Vec<GlobCase>,
    match_cases: Vec<MatchCase>,
    precedence_cases: Vec<PrecedenceCase>,
    decomposition_cases: Vec<DecompositionCase>,
    overlap_cases: Vec<OverlapCase>,
    catalogs: Vec<Catalog>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedMethods {
    accepted: Vec<String>,
    parsed_but_unsupported: Vec<String>,
    any_representation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedActionClasses {
    expected_count: usize,
    accepted_sentinels: Vec<String>,
    rejected: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogSummary {
    selectable_templates: usize,
    source_rules: usize,
    template_host_entries: usize,
    distinct_normalized_host_patterns: usize,
    excluded_templates: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Contract {
    Observed,
    Agreed,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Accept,
    Reject,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseCase {
    id: String,
    contract: Contract,
    source: String,
    outcome: Outcome,
    rule_count: Option<usize>,
    error_code: Option<String>,
    document: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationCase {
    id: String,
    contract: Contract,
    source: String,
    outcome: Outcome,
    error_code: Option<String>,
    document: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNormalizationCase {
    id: String,
    contract: Contract,
    source: String,
    input: String,
    output: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathNormalizationCase {
    id: String,
    contract: Contract,
    source: String,
    input: String,
    output: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobCase {
    id: String,
    contract: Contract,
    source: String,
    pattern: String,
    candidate: String,
    matches: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MatchTarget {
    MappingTable,
    IntentNormalizer,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ExpectedMatchResult {
    Matched,
    UnclassifiedProtected,
    NormalizationDenied,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchCase {
    id: String,
    contract: Contract,
    source: String,
    target: MatchTarget,
    request_method: String,
    request_authority: String,
    request_path: String,
    is_https: bool,
    result: ExpectedMatchResult,
    action_class: Option<String>,
    normalized_authority: Option<String>,
    dispatch_authority: Option<String>,
    normalized_path: Option<String>,
    rules_toml: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrecedenceCase {
    id: String,
    contract: Contract,
    source: String,
    request_method: String,
    request_authority: String,
    request_path: String,
    winning_action_class: String,
    rules_toml: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecompositionCase {
    id: String,
    contract: Contract,
    source: String,
    full_host: String,
    owner_host: String,
    subdomain: String,
    outcome: Outcome,
    normalized_full_host: Option<String>,
    normalized_owner_host: Option<String>,
    recomposed_host: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlapCase {
    id: String,
    contract: Contract,
    source: String,
    left: String,
    right: String,
    overlaps: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    selection: String,
    source: String,
    rule_count: usize,
    hosts: Vec<CatalogHost>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogHost {
    pattern: String,
    owner_host: String,
    subdomain: String,
    rule_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct Decomposition {
    full: String,
    owner: String,
    recomposed: String,
}

fn decode_corpus(source: &str) -> anyhow::Result<Corpus> {
    let corpus: Corpus = toml::from_str(source)?;
    anyhow::ensure!(
        corpus.schema_version == SUPPORTED_CORPUS_SCHEMA,
        "unsupported mapping corpus schema {}; expected {}",
        corpus.schema_version,
        SUPPORTED_CORPUS_SCHEMA
    );

    let ids = corpus
        .parse_cases
        .iter()
        .map(|case| case.id.as_str())
        .chain(corpus.validation_cases.iter().map(|case| case.id.as_str()))
        .chain(
            corpus
                .host_normalization_cases
                .iter()
                .map(|case| case.id.as_str()),
        )
        .chain(
            corpus
                .path_normalization_cases
                .iter()
                .map(|case| case.id.as_str()),
        )
        .chain(corpus.glob_cases.iter().map(|case| case.id.as_str()))
        .chain(corpus.match_cases.iter().map(|case| case.id.as_str()))
        .chain(corpus.precedence_cases.iter().map(|case| case.id.as_str()))
        .chain(
            corpus
                .decomposition_cases
                .iter()
                .map(|case| case.id.as_str()),
        )
        .chain(corpus.overlap_cases.iter().map(|case| case.id.as_str()));
    let mut seen = HashSet::new();
    for id in ids {
        anyhow::ensure!(
            seen.insert(id),
            "duplicate mapping compatibility case ID '{id}'"
        );
    }
    Ok(corpus)
}

fn load_corpus() -> anyhow::Result<Corpus> {
    decode_corpus(CORPUS)
}

fn assert_case_metadata(id: &str, contract: Contract, source: &str, expected: Contract) {
    assert!(!id.is_empty(), "case ID must not be empty");
    assert_eq!(contract, expected, "unexpected contract for case '{id}'");
    assert!(!source.trim().is_empty(), "missing source for case '{id}'");
    match contract {
        Contract::Observed => assert!(
            source.starts_with("crates/"),
            "observed case '{id}' has non-code source '{source}'"
        ),
        Contract::Agreed => assert!(
            source.starts_with("compatibility/mapping/README.md::"),
            "agreed case '{id}' has non-contract source '{source}'"
        ),
    }
}

fn verify_metadata_and_ids(corpus: &Corpus) {
    assert_eq!(corpus.observed_revision, OBSERVED_REVISION);
    assert!(
        corpus
            .observed_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()),
        "observed revision must be a hexadecimal commit ID"
    );

    macro_rules! observed_cases {
        ($cases:expr) => {
            for case in $cases {
                assert_case_metadata(&case.id, case.contract, &case.source, Contract::Observed);
            }
        };
    }
    macro_rules! agreed_cases {
        ($cases:expr) => {
            for case in $cases {
                assert_case_metadata(&case.id, case.contract, &case.source, Contract::Agreed);
            }
        };
    }

    observed_cases!(&corpus.parse_cases);
    observed_cases!(&corpus.validation_cases);
    observed_cases!(&corpus.host_normalization_cases);
    observed_cases!(&corpus.path_normalization_cases);
    observed_cases!(&corpus.glob_cases);
    observed_cases!(&corpus.match_cases);
    observed_cases!(&corpus.precedence_cases);
    agreed_cases!(&corpus.decomposition_cases);
    agreed_cases!(&corpus.overlap_cases);
}

fn parse_error_code(error: &toml::de::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("missing field") {
        "missing_field"
    } else if message.contains("invalid HTTP method") {
        "invalid_method_syntax"
    } else {
        "wrong_type"
    }
}

fn validation_error_code(error: &str) -> Option<&'static str> {
    if error.contains("contains no rules") {
        Some("empty_rules")
    } else if error.contains("host must not be empty") {
        Some("empty_host")
    } else if error.contains("normalizes to a host with an empty name") {
        Some("empty_normalized_host")
    } else if error.contains("would normalize") {
        Some("implicit_catch_all")
    } else if error.contains("action_class must not be empty") {
        Some("empty_action_class")
    } else if error.contains("invalid HTTP method") {
        Some("unsupported_method")
    } else if error.contains("duplicate mapping tuple") {
        Some("duplicate_tuple")
    } else if error.contains("not in the built-in FEP action class registry") {
        Some("unknown_action_class")
    } else {
        None
    }
}

fn parse_rules(document: &str) -> anyhow::Result<MappingRulesFile> {
    Ok(toml::from_str(document)?)
}

fn build_table(document: &str) -> anyhow::Result<MappingTable> {
    let file = parse_rules(document)?;
    Ok(MappingTable::from_config(
        &file,
        &ActionClassRegistry::v0_1(),
    )?)
}

fn request(method: Method, authority: Authority, path: &str, is_https: bool) -> RawRequest {
    RawRequest {
        method,
        host: authority,
        path: path.to_string(),
        headers: HeaderMap::new(),
        body: None,
        is_https,
    }
}

fn verify_parser_and_validation(corpus: &Corpus) {
    for case in &corpus.parse_cases {
        let parsed = toml::from_str::<MappingRulesFile>(&case.document);
        match (case.outcome, parsed) {
            (Outcome::Accept, Ok(file)) => assert_eq!(
                Some(file.rule_count()),
                case.rule_count,
                "rule count mismatch for case '{}'",
                case.id
            ),
            (Outcome::Reject, Err(error)) => assert_eq!(
                Some(parse_error_code(&error)),
                case.error_code.as_deref(),
                "parse error code mismatch for case '{}': {error}",
                case.id
            ),
            (Outcome::Accept, Err(error)) => {
                panic!("case '{}' unexpectedly rejected: {error}", case.id)
            }
            (Outcome::Reject, Ok(_)) => panic!("case '{}' unexpectedly parsed", case.id),
        }
    }

    for case in &corpus.validation_cases {
        let file = parse_rules(&case.document).unwrap_or_else(|error| {
            panic!("case '{}' must parse before validation: {error}", case.id)
        });
        let result = MappingTable::from_config(&file, &ActionClassRegistry::v0_1());
        match (case.outcome, result) {
            (Outcome::Accept, Ok(_)) => {}
            (Outcome::Reject, Err(error)) => assert_eq!(
                validation_error_code(&error.to_string()),
                case.error_code.as_deref(),
                "validation error code mismatch for case '{}': {error}",
                case.id
            ),
            (Outcome::Accept, Err(error)) => {
                panic!("case '{}' unexpectedly rejected: {error}", case.id)
            }
            (Outcome::Reject, Ok(_)) => panic!("case '{}' unexpectedly validated", case.id),
        }
    }
}

fn verify_observed_catalog_metadata(corpus: &Corpus) -> anyhow::Result<()> {
    assert_eq!(corpus.observed_methods.any_representation, "omitted");
    assert_eq!(
        corpus.observed_methods.accepted,
        [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"
        ]
    );
    for method in &corpus.observed_methods.accepted {
        let document = format!(
            "[[rules]]\nmethod = {method:?}\nhost = \"example.com\"\naction_class = \"communication.external.read\"\n"
        );
        build_table(&document)
            .unwrap_or_else(|error| panic!("accepted method '{method}' was rejected: {error}"));
    }
    for method in &corpus.observed_methods.parsed_but_unsupported {
        let parsed = Method::from_str(method)
            .unwrap_or_else(|error| panic!("method '{method}' must parse: {error}"));
        let document = format!(
            "[[rules]]\nmethod = {:?}\nhost = \"example.com\"\naction_class = \"communication.external.read\"\n",
            parsed.as_str()
        );
        let file = parse_rules(&document)?;
        let error = MappingTable::from_config(&file, &ActionClassRegistry::v0_1())
            .err()
            .unwrap_or_else(|| panic!("unsupported method '{method}' passed Sidecar validation"));
        assert_eq!(
            validation_error_code(&error.to_string()),
            Some("unsupported_method")
        );
    }

    assert_eq!(
        corpus.observed_action_classes.expected_count,
        ActionClass::ALL.len()
    );
    for class in &corpus.observed_action_classes.accepted_sentinels {
        let document = format!("[[rules]]\nhost = \"example.com\"\naction_class = {class:?}\n");
        build_table(&document).unwrap_or_else(|error| {
            panic!("accepted action class '{class}' was rejected: {error}")
        });
    }
    for class in &corpus.observed_action_classes.rejected {
        let document = format!("[[rules]]\nhost = \"example.com\"\naction_class = {class:?}\n");
        let file = parse_rules(&document)?;
        assert!(
            MappingTable::from_config(&file, &ActionClassRegistry::v0_1()).is_err(),
            "rejected action class '{class}' was accepted"
        );
    }
    Ok(())
}

fn verify_normalization(corpus: &Corpus) -> anyhow::Result<()> {
    for case in &corpus.host_normalization_cases {
        let document = format!(
            "[[rules]]\nhost = {:?}\naction_class = \"communication.external.read\"\n",
            case.input
        );
        let table = build_table(&document)?;
        let authority = Authority::from_str(&case.output)?;
        match table.find_match(&Method::GET, &authority, "/") {
            MatchResult::Matched(rule) => assert_eq!(
                rule.host_pattern, case.output,
                "host normalization mismatch for case '{}'",
                case.id
            ),
            other @ MatchResult::UnclassifiedProtected => panic!(
                "case '{}' did not match normalized host: {other:?}",
                case.id
            ),
        }
    }

    for case in &corpus.path_normalization_cases {
        let table = build_table(
            "[[rules]]\nhost = \"example.com\"\naction_class = \"communication.external.read\"\n",
        )?;
        let envelope = IntentNormalizer::new(table)
            .normalize(&request(
                Method::GET,
                Authority::from_static("example.com"),
                &case.input,
                true,
            ))
            .unwrap_or_else(|decision| panic!("case '{}' was denied: {decision:?}", case.id));
        let normalized_path = envelope.intent().resource["path"]
            .split('?')
            .next()
            .unwrap_or_default();
        assert_eq!(
            normalized_path, case.output,
            "path mismatch for case '{}'",
            case.id
        );
    }
    Ok(())
}

fn verify_globs(corpus: &Corpus) -> anyhow::Result<()> {
    for case in &corpus.glob_cases {
        let document = format!(
            "[[rules]]\nhost = \"example.com\"\npath = {:?}\naction_class = \"communication.external.read\"\n",
            case.pattern
        );
        let table = build_table(&document)?;
        let matched = matches!(
            table.find_match(
                &Method::GET,
                &Authority::from_static("example.com"),
                &case.candidate
            ),
            MatchResult::Matched(_)
        );
        assert_eq!(
            matched, case.matches,
            "glob mismatch for case '{}'",
            case.id
        );
    }
    Ok(())
}

fn assert_table_result(case: &MatchCase, result: MatchResult<'_>) {
    match (case.result, result) {
        (ExpectedMatchResult::Matched, MatchResult::Matched(rule)) => assert_eq!(
            Some(rule.action_class.as_str()),
            case.action_class.as_deref(),
            "action class mismatch for case '{}'",
            case.id
        ),
        (ExpectedMatchResult::UnclassifiedProtected, MatchResult::UnclassifiedProtected) => {}
        (_, actual) => panic!("unexpected table result for case '{}': {actual:?}", case.id),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "match and precedence fixtures share one Sidecar runtime setup"
)]
fn verify_matches_and_precedence(corpus: &Corpus) -> anyhow::Result<()> {
    for case in &corpus.match_cases {
        let method = Method::from_str(&case.request_method)?;
        let authority = Authority::from_str(&case.request_authority)?;
        if let Some(expected) = &case.normalized_path {
            let probe = build_table(
                "[[rules]]\nhost = \"*\"\naction_class = \"communication.external.read\"\n",
            )?;
            let envelope = IntentNormalizer::new(probe)
                .normalize(&request(
                    method.clone(),
                    authority.clone(),
                    &case.request_path,
                    case.is_https,
                ))
                .unwrap_or_else(|decision| {
                    panic!("path probe for case '{}' was denied: {decision:?}", case.id)
                });
            assert_eq!(
                envelope.intent().resource["path"].split('?').next(),
                Some(expected.as_str()),
                "normalized path mismatch for case '{}'",
                case.id
            );
        }
        let table = build_table(&case.rules_toml)?;
        if let Some(normalized_authority) = &case.normalized_authority {
            let normalized = Authority::from_str(normalized_authority)?;
            assert!(
                matches!(
                    table.find_match(&method, &normalized, &case.request_path),
                    MatchResult::Matched(_)
                ),
                "normalized authority did not match for case '{}'",
                case.id
            );
        }

        match case.target {
            MatchTarget::MappingTable => {
                assert_table_result(
                    case,
                    table.find_match(&method, &authority, &case.request_path),
                );
            }
            MatchTarget::IntentNormalizer => {
                if case.result == ExpectedMatchResult::NormalizationDenied {
                    assert!(
                        matches!(
                            table.find_match(&method, &authority, &case.request_path),
                            MatchResult::Matched(_)
                        ),
                        "normalization-denied case '{}' must match before envelope conversion",
                        case.id
                    );
                }
                let result = IntentNormalizer::new(table).normalize(&request(
                    method,
                    authority,
                    &case.request_path,
                    case.is_https,
                ));
                match (case.result, result) {
                    (ExpectedMatchResult::Matched, Ok(envelope)) => {
                        assert_eq!(
                            Some(envelope.intent().action_class.as_str()),
                            case.action_class.as_deref(),
                            "action class mismatch for case '{}'",
                            case.id
                        );
                        if let Some(expected) = &case.dispatch_authority {
                            assert_eq!(
                                envelope.intent().resource.get("host"),
                                Some(expected),
                                "dispatch authority mismatch for case '{}'",
                                case.id
                            );
                        }
                    }
                    (
                        ExpectedMatchResult::NormalizationDenied,
                        Err(EnforcementDecision::Deny { detail, .. }),
                    ) => assert!(
                        detail.starts_with("unrecognized HTTP method:"),
                        "normalization-denied case '{}' failed for the wrong reason: {detail}",
                        case.id
                    ),
                    (
                        ExpectedMatchResult::UnclassifiedProtected,
                        Err(EnforcementDecision::Deny { detail, .. }),
                    ) => assert!(
                        detail.starts_with("protected action could not be classified:"),
                        "unclassified case '{}' failed for the wrong reason: {detail}",
                        case.id
                    ),
                    (_, actual) => panic!(
                        "unexpected normalizer result for case '{}': {actual:?}",
                        case.id
                    ),
                }
            }
        }
    }

    for case in &corpus.precedence_cases {
        let table = build_table(&case.rules_toml)?;
        let method = Method::from_str(&case.request_method)?;
        let authority = Authority::from_str(&case.request_authority)?;
        match table.find_match(&method, &authority, &case.request_path) {
            MatchResult::Matched(rule) => assert_eq!(
                rule.action_class, case.winning_action_class,
                "precedence mismatch for case '{}'",
                case.id
            ),
            other @ MatchResult::UnclassifiedProtected => {
                panic!("precedence case '{}' did not match: {other:?}", case.id)
            }
        }
    }
    Ok(())
}

fn validate_port(port: Option<&str>) -> Result<(), &'static str> {
    if let Some(port) = port {
        let number = port.parse::<u16>().map_err(|_| "invalid_owner")?;
        if number == 0 {
            return Err("invalid_owner");
        }
    }
    Ok(())
}

fn owner_kind(name: &str) -> Result<&'static str, &'static str> {
    if name == "*" {
        return Ok("catch_all");
    }
    if name.parse::<Ipv4Addr>().is_ok() {
        return Ok("ipv4");
    }
    if let Some(literal) = name
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        literal.parse::<Ipv6Addr>().map_err(|_| "invalid_owner")?;
        return Ok("ipv6");
    }
    if name.contains('*')
        || name.len() > 253
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("invalid_owner");
    }
    Ok("dns")
}

fn decompose(case: &DecompositionCase) -> Result<Decomposition, &'static str> {
    let normalized_full_host = normalize_mapping_host(&case.full_host);
    let normalized_owner_host = normalize_mapping_host(&case.owner_host);
    let (full_name, full_port) = split_mapping_authority(&normalized_full_host);
    let (owner_name, owner_port) = split_mapping_authority(&normalized_owner_host);
    validate_port(owner_port.as_deref())?;
    let kind = owner_kind(&owner_name)?;

    if case.subdomain.starts_with('.')
        || case.subdomain.ends_with('.')
        || case.subdomain.split('.').any(str::is_empty) && !case.subdomain.is_empty()
    {
        return Err("invalid_relative_subdomain");
    }
    if kind != "dns" && !case.subdomain.is_empty() {
        return Err("non_dns_owner_requires_empty_subdomain");
    }
    if full_port != owner_port {
        return Err("owner_port_mismatch");
    }

    let recomposed_name = if case.subdomain.is_empty() {
        owner_name
    } else {
        format!("{}.{}", case.subdomain, owner_name)
    };
    if recomposed_name != full_name {
        return Err("owner_not_suffix");
    }
    let recomposed_host = owner_port.map_or_else(
        || recomposed_name.clone(),
        |port| format!("{recomposed_name}:{port}"),
    );
    Ok(Decomposition {
        full: normalized_full_host,
        owner: normalized_owner_host,
        recomposed: recomposed_host,
    })
}

fn verify_agreed_cases(corpus: &Corpus) {
    for case in &corpus.decomposition_cases {
        match (case.outcome, decompose(case)) {
            (Outcome::Accept, Ok(actual)) => {
                assert_eq!(
                    Some(actual.full.as_str()),
                    case.normalized_full_host.as_deref(),
                    "normalized full host mismatch for case '{}'",
                    case.id
                );
                assert_eq!(
                    Some(actual.owner.as_str()),
                    case.normalized_owner_host.as_deref(),
                    "normalized owner mismatch for case '{}'",
                    case.id
                );
                assert_eq!(
                    Some(actual.recomposed.as_str()),
                    case.recomposed_host.as_deref(),
                    "recomposition mismatch for case '{}'",
                    case.id
                );
            }
            (Outcome::Reject, Err(code)) => assert_eq!(
                Some(code),
                case.error_code.as_deref(),
                "decomposition error mismatch for case '{}'",
                case.id
            ),
            (Outcome::Accept, Err(code)) => {
                panic!("case '{}' unexpectedly rejected: {code}", case.id)
            }
            (Outcome::Reject, Ok(actual)) => {
                panic!("case '{}' unexpectedly accepted: {actual:?}", case.id)
            }
        }
    }

    for case in &corpus.overlap_cases {
        let left = normalize_mapping_host(&case.left);
        let right = normalize_mapping_host(&case.right);
        assert_eq!(
            glob_patterns_overlap(&left, &right),
            case.overlaps,
            "left-to-right overlap mismatch for case '{}'",
            case.id
        );
        assert_eq!(
            glob_patterns_overlap(&right, &left),
            case.overlaps,
            "right-to-left overlap mismatch for case '{}'",
            case.id
        );
    }
}

fn openfirma_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn expected_catalog_path(selection: &str) -> Option<&'static str> {
    match selection {
        "anthropic" => Some("crates/firma/templates/mappings/anthropic.toml"),
        "cargo" => Some("crates/firma/templates/mappings/cargo-registry.toml"),
        "copilot" => Some("crates/firma/templates/mappings/copilot.toml"),
        "composio" => Some("crates/firma/templates/mappings/composio.toml"),
        "github" => Some("crates/firma/templates/mappings/github.toml"),
        "gmail" => Some("crates/firma/templates/mappings/gmail.toml"),
        "npm" => Some("crates/firma/templates/mappings/npm.toml"),
        "openai" => Some("crates/firma/templates/mappings/openai.toml"),
        "pypi" => Some("crates/firma/templates/mappings/pypi.toml"),
        "stripe" => Some("crates/firma/templates/mappings/stripe.toml"),
        "vscode" => Some("crates/firma/templates/mappings/vscode.toml"),
        _ => None,
    }
}

fn verify_catalogs(corpus: &Corpus) -> anyhow::Result<()> {
    let root = openfirma_root();
    let mut selections = HashSet::new();
    let mut normalized_patterns = HashSet::new();
    let mut source_rules = 0usize;
    let mut host_entries = 0usize;

    for catalog in &corpus.catalogs {
        assert!(
            selections.insert(catalog.selection.as_str()),
            "duplicate catalog selection '{}'",
            catalog.selection
        );
        assert_eq!(
            Some(catalog.source.as_str()),
            expected_catalog_path(&catalog.selection),
            "catalog path mismatch for selection '{}'",
            catalog.selection
        );
        let source = std::fs::read_to_string(root.join(&catalog.source))?;
        let file = parse_rules(&source)?;
        assert_eq!(
            file.rule_count(),
            catalog.rule_count,
            "catalog rule count mismatch for '{}'",
            catalog.selection
        );
        MappingTable::from_config(&file, &ActionClassRegistry::v0_1())?;

        let mut actual_hosts: HashMap<String, usize> = HashMap::new();
        for rule in &file.rules {
            *actual_hosts
                .entry(normalize_mapping_host(&rule.host))
                .or_default() += 1;
        }
        assert_eq!(
            actual_hosts.len(),
            catalog.hosts.len(),
            "catalog host-entry count mismatch for '{}'",
            catalog.selection
        );
        for host in &catalog.hosts {
            assert_eq!(
                actual_hosts.get(&normalize_mapping_host(&host.pattern)),
                Some(&host.rule_count),
                "host rule count mismatch for '{}' in '{}'",
                host.pattern,
                catalog.selection
            );
            let decomposition_case = DecompositionCase {
                id: format!("catalog-{}-{}", catalog.selection, host.pattern),
                contract: Contract::Agreed,
                source: "compatibility/mapping/README.md::Catalog Inventory".to_string(),
                full_host: host.pattern.clone(),
                owner_host: host.owner_host.clone(),
                subdomain: host.subdomain.clone(),
                outcome: Outcome::Accept,
                normalized_full_host: None,
                normalized_owner_host: None,
                recomposed_host: None,
                error_code: None,
            };
            decompose(&decomposition_case).unwrap_or_else(|code| {
                panic!(
                    "catalog host '{}' in '{}' does not decompose: {code}",
                    host.pattern, catalog.selection
                )
            });
            normalized_patterns.insert(normalize_mapping_host(&host.pattern));
        }
        source_rules += catalog.rule_count;
        host_entries += catalog.hosts.len();
    }

    assert_eq!(
        selections.len(),
        corpus.catalog_summary.selectable_templates
    );
    assert_eq!(source_rules, corpus.catalog_summary.source_rules);
    assert_eq!(host_entries, corpus.catalog_summary.template_host_entries);
    assert_eq!(
        normalized_patterns.len(),
        corpus.catalog_summary.distinct_normalized_host_patterns
    );
    assert_eq!(corpus.catalog_summary.excluded_templates, ["custom.toml"]);
    for excluded in &corpus.catalog_summary.excluded_templates {
        assert!(
            root.join("crates/firma/templates/mappings")
                .join(excluded)
                .is_file(),
            "excluded catalog template '{excluded}' does not exist"
        );
        assert!(
            corpus
                .catalogs
                .iter()
                .all(|catalog| !catalog.source.ends_with(excluded)),
            "excluded template '{excluded}' was included in the catalog"
        );
    }
    Ok(())
}

#[test]
fn sidecar_executes_the_complete_mapping_compatibility_corpus() -> anyhow::Result<()> {
    let corpus = load_corpus()?;
    verify_metadata_and_ids(&corpus);
    verify_observed_catalog_metadata(&corpus)?;
    verify_parser_and_validation(&corpus);
    verify_normalization(&corpus)?;
    verify_globs(&corpus)?;
    verify_matches_and_precedence(&corpus)?;
    verify_agreed_cases(&corpus);
    verify_catalogs(&corpus)?;
    Ok(())
}

#[test]
fn corpus_schema_rejects_unknown_fields_versions_and_duplicate_ids() {
    let unknown = CORPUS.replacen(
        "schema_version = 1",
        "schema_version = 1\nunknown = true",
        1,
    );
    assert!(decode_corpus(&unknown).is_err());

    let unsupported = CORPUS.replacen("schema_version = 1", "schema_version = 2", 1);
    assert!(decode_corpus(&unsupported).is_err());

    let duplicate = CORPUS.replacen(
        "id = \"normalize-root-path\"",
        "id = \"parse-minimal-rule\"",
        1,
    );
    assert!(decode_corpus(&duplicate).is_err());
}
