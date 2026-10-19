//! Black-box verification of the selectable mapping catalog.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test failures include the affected catalog selection"
)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use firma_http::{Authority, Method};
use firma_sidecar::config::MappingRulesFile;
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::normalizer::{MappingTable, MatchResult};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../../compatibility/mapping/cases.toml");

const SUPPORTED_SCHEMA_VERSION: i64 = 1;

#[derive(Deserialize)]
struct Corpus {
    catalogs: Vec<Catalog>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    selection: String,
    source: String,
    rule_count: usize,
    hosts: Vec<CatalogHost>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogHost {
    pattern: String,
    owner_host: String,
    subdomain: String,
    rule_count: usize,
}

fn firma() -> Command {
    Command::new(env!("CARGO_BIN_EXE_firma"))
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn listed_mappings(stdout: &[u8]) -> Vec<String> {
    let stdout = String::from_utf8_lossy(stdout);
    let mappings = stdout
        .split_once("Mappings  (--mapping, repeatable):")
        .map_or_else(
            || panic!("template listing omitted the mapping section:\n{stdout}"),
            |(_, mappings)| mappings,
        );
    mappings
        .lines()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| !line.trim().is_empty())
        .map(|line| {
            assert!(line.starts_with("  "), "unexpected mapping row: {line}");
            line.split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("empty mapping row: {line}"))
        })
        .map(str::to_owned)
        .collect()
}

fn reject_unknown_fields(
    table: &toml::Table,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    for field in table.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(format!("unknown field `{field}` in {context}"));
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the explicit fixture schema keeps strict unknown-field checks auditable"
)]
fn decode_corpus(source: &str) -> Result<Corpus, String> {
    let value = source
        .parse::<toml::Table>()
        .map_err(|error| error.to_string())?;
    reject_unknown_fields(
        &value,
        &[
            "schema_version",
            "observed_revision",
            "observed_methods",
            "observed_action_classes",
            "catalog_summary",
            "parse_cases",
            "validation_cases",
            "host_normalization_cases",
            "path_normalization_cases",
            "glob_cases",
            "match_cases",
            "precedence_cases",
            "decomposition_cases",
            "overlap_cases",
            "catalogs",
        ],
        "mapping corpus",
    )?;
    let schema_version = value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| "mapping corpus lacks integer schema_version".to_owned())?;
    if schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(format!(
            "unsupported mapping corpus schema {schema_version}"
        ));
    }

    for (section, allowed) in [
        (
            "observed_methods",
            &["accepted", "parsed_but_unsupported", "any_representation"][..],
        ),
        (
            "observed_action_classes",
            &["expected_count", "accepted_sentinels", "rejected"],
        ),
        (
            "catalog_summary",
            &[
                "selectable_templates",
                "source_rules",
                "template_host_entries",
                "distinct_normalized_host_patterns",
                "excluded_templates",
            ],
        ),
    ] {
        let table = value
            .get(section)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("mapping corpus lacks `{section}` table"))?;
        reject_unknown_fields(table, allowed, section)?;
    }

    let sections = [
        (
            "parse_cases",
            &[
                "id",
                "contract",
                "source",
                "outcome",
                "rule_count",
                "error_code",
                "document",
            ][..],
        ),
        (
            "validation_cases",
            &[
                "id",
                "contract",
                "source",
                "outcome",
                "error_code",
                "document",
            ],
        ),
        (
            "host_normalization_cases",
            &["id", "contract", "source", "input", "output"],
        ),
        (
            "path_normalization_cases",
            &["id", "contract", "source", "input", "output"],
        ),
        (
            "glob_cases",
            &[
                "id",
                "contract",
                "source",
                "pattern",
                "candidate",
                "matches",
            ],
        ),
        (
            "match_cases",
            &[
                "id",
                "contract",
                "source",
                "target",
                "request_method",
                "request_authority",
                "request_path",
                "is_https",
                "result",
                "action_class",
                "normalized_authority",
                "dispatch_authority",
                "normalized_path",
                "rules_toml",
            ],
        ),
        (
            "precedence_cases",
            &[
                "id",
                "contract",
                "source",
                "request_method",
                "request_authority",
                "request_path",
                "winning_action_class",
                "rules_toml",
            ],
        ),
        (
            "decomposition_cases",
            &[
                "id",
                "contract",
                "source",
                "full_host",
                "owner_host",
                "subdomain",
                "outcome",
                "normalized_full_host",
                "normalized_owner_host",
                "recomposed_host",
                "error_code",
            ],
        ),
        (
            "overlap_cases",
            &["id", "contract", "source", "left", "right", "overlaps"],
        ),
    ];
    let mut ids = HashSet::new();
    for (section, allowed) in sections {
        let cases = value
            .get(section)
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("mapping corpus lacks `{section}` array"))?;
        for case in cases {
            let case = case
                .as_table()
                .ok_or_else(|| format!("{section} contains a non-table case"))?;
            reject_unknown_fields(case, allowed, section)?;
            let id = case
                .get("id")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("{section} case lacks string id"))?;
            if !ids.insert(id) {
                return Err(format!("duplicate mapping compatibility case ID `{id}`"));
            }
        }
    }

    toml::Value::Table(value)
        .try_into::<Corpus>()
        .map_err(|error| error.to_string())
}

fn extract_dry_run_file<'a>(stdout: &'a str, file_name: &str) -> &'a str {
    let header = stdout
        .lines()
        .find(|line| line.starts_with("=== ") && line.trim_end_matches(" ===").ends_with(file_name))
        .unwrap_or_else(|| panic!("missing dry-run file {file_name} in stdout:\n{stdout}"));
    let content = stdout.split_once(header).map_or_else(
        || panic!("missing dry-run header {header}"),
        |(_, content)| content.trim_start_matches('\n'),
    );
    let end = content.find("\n=== ").unwrap_or(content.len());
    content[..end].trim_end_matches('\n')
}

fn openfirma_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn selectable_mapping_catalog_matches_the_shared_corpus() {
    let corpus = decode_corpus(CORPUS).expect("parse mapping compatibility corpus");
    let expected_selections = corpus
        .catalogs
        .iter()
        .map(|catalog| catalog.selection.clone())
        .collect::<Vec<_>>();

    let listing = firma()
        .args(["config", "--list-templates"])
        .output()
        .expect("spawn firma config --list-templates");
    assert_success(&listing, "template listing");
    assert_eq!(listed_mappings(&listing.stdout), expected_selections);

    let temp = tempfile::tempdir().expect("create temporary config root");
    let config_dir = temp.path().join("config");
    let state_dir = temp.path().join("state");
    let mut command = firma();
    command.args(["config", "--yes", "--dry-run", "--output-dir"]);
    command
        .arg(&config_dir)
        .args(["--state-dir"])
        .arg(&state_dir);
    for catalog in &corpus.catalogs {
        command.arg("--mapping").arg(&catalog.selection);
    }
    let generated = command.output().expect("spawn firma config --dry-run");
    assert_success(&generated, "mapping template generation");
    let stdout = String::from_utf8(generated.stdout).expect("dry-run output must be UTF-8");
    let root = openfirma_root();
    let mut matchers = HashMap::new();

    for catalog in &corpus.catalogs {
        assert!(catalog.rule_count > 0, "{}", catalog.selection);
        assert!(!catalog.hosts.is_empty(), "{}", catalog.selection);
        assert_eq!(
            catalog
                .hosts
                .iter()
                .map(|host| host.rule_count)
                .sum::<usize>(),
            catalog.rule_count,
            "{}",
            catalog.selection
        );
        for host in &catalog.hosts {
            assert!(!host.pattern.is_empty(), "{}", catalog.selection);
            assert!(!host.owner_host.is_empty(), "{}", catalog.selection);
            assert!(!host.subdomain.starts_with('.'), "{}", catalog.selection);
        }
        let generated_name = format!("mappings/{}.toml", catalog.selection);
        let actual = extract_dry_run_file(&stdout, &generated_name);
        let expected = std::fs::read_to_string(root.join(&catalog.source))
            .unwrap_or_else(|error| panic!("{}: {error}", catalog.source));
        assert_eq!(
            actual,
            expected.trim_end_matches('\n'),
            "{}",
            catalog.selection
        );

        // The standard package merges these sources. Source order must never
        // decide which action class wins for an identical runtime matcher.
        let file: MappingRulesFile =
            toml::from_str(actual).unwrap_or_else(|error| panic!("{}: {error}", catalog.selection));
        assert_eq!(
            file.rules.len(),
            catalog.rule_count,
            "{}",
            catalog.selection
        );
        for rule in file.rules {
            let key = (
                rule.method
                    .as_ref()
                    .map(|method| method.as_str().to_owned()),
                firma_core::normalize_mapping_host(&rule.host),
                rule.path.unwrap_or_default(),
            );
            if let Some((source, action_class)) = matchers.insert(
                key.clone(),
                (catalog.selection.as_str(), rule.action_class.clone()),
            ) {
                assert_eq!(
                    action_class, rule.action_class,
                    "conflicting effective matcher {key:?}: {source} assigns {action_class}, {} assigns {}",
                    catalog.selection, rule.action_class
                );
            }
        }
    }
}

#[test]
fn opaque_github_api_tunnels_cannot_be_classified_as_read_only() {
    let root = openfirma_root();
    let registry = ActionClassRegistry::v0_1();
    let github: MappingRulesFile = toml::from_str(
        &std::fs::read_to_string(root.join("crates/firma/templates/mappings/github.toml"))
            .expect("read GitHub mapping"),
    )
    .expect("parse GitHub mapping");
    let github = MappingTable::from_config(&github, &registry).expect("load GitHub mapping");
    // Production CONNECT requests carry "/" as the path
    // (`build_raw_request_head` maps `is_connect` to "/"): an omitted-path
    // CONNECT rule must match it, and the reference REST writes below pin
    // the coarse tunnel class to the same write class.
    let api_host = Authority::from_static("api.github.com");
    let MatchResult::Matched(write) =
        github.find_match(&Method::POST, &api_host, "/repos/org/repo/git/refs")
    else {
        panic!("GitHub reference creation must be classified");
    };
    assert_eq!(write.action_class, "code.write");
    let git_host = Authority::from_static("github.com");
    let MatchResult::Matched(push) =
        github.find_match(&Method::POST, &git_host, "/org/repo.git/git-receive-pack")
    else {
        panic!("GitHub push must be classified");
    };
    assert_eq!(push.action_class, "code.write");

    let mut unsafe_tunnels = Vec::new();
    // Each selection as a profile actually loads it: `vscode` reaches both
    // hosts but contributes no CONNECT rule for them, leaving them to the
    // `github` mapping its profile always selects alongside it.
    for (selection, templates) in [
        ("github", &["github"][..]),
        ("copilot", &["copilot"][..]),
        ("vscode", &["vscode", "github"][..]),
    ] {
        let mut file = MappingRulesFile { rules: Vec::new() };
        for template in templates {
            let source = root.join(format!("crates/firma/templates/mappings/{template}.toml"));
            let selected: MappingRulesFile =
                toml::from_str(&std::fs::read_to_string(source).expect("read selected mapping"))
                    .expect("parse selected mapping");
            file.rules.extend(selected.rules);
        }
        let table = MappingTable::from_config(&file, &registry).expect("load selected mapping");
        for (host, host_name, expected) in [
            (&api_host, "api.github.com", write),
            (&git_host, "github.com", push),
        ] {
            match table.find_match(&Method::CONNECT, host, "/") {
                MatchResult::Matched(tunnel) => {
                    if tunnel.action_class != expected.action_class {
                        unsafe_tunnels
                            .push(format!("{selection} {host_name}: {}", tunnel.action_class));
                    }
                }
                other @ MatchResult::UnclassifiedProtected => {
                    panic!("{selection} must classify the {host_name} tunnel, got {other:?}")
                }
            }
        }
    }
    assert!(
        unsafe_tunnels.is_empty(),
        "CONNECT hides HTTP method and path; read-only access would authorize GitHub API writes via: {unsafe_tunnels:?}"
    );
}

#[test]
fn release_demo_classifies_model_requests_without_unprotecting_other_hosts() {
    let directory = openfirma_root().join("examples/demo");
    let config: firma_config_schema::authority::AuthorityConfig = toml::from_str::<toml::Value>(
        &std::fs::read_to_string(directory.join("firma.toml")).expect("read demo config"),
    )
    .expect("parse demo config")["authority"]
        .clone()
        .try_into()
        .expect("parse demo Authority");
    let mut file = MappingRulesFile { rules: Vec::new() };
    for path in config.mapping_rules_paths {
        let source = directory.join(path);
        let selected: MappingRulesFile =
            toml::from_str(&std::fs::read_to_string(source).expect("read demo mapping"))
                .expect("parse demo mapping");
        file.rules.extend(selected.rules);
    }
    let table = MappingTable::from_config(&file, &ActionClassRegistry::v0_1())
        .expect("compile demo producer mappings");
    let MatchResult::Matched(model_request) = table.find_match(
        &Method::POST,
        &Authority::from_static("api.openai.com"),
        "/v1/responses",
    ) else {
        panic!("the hero demo must classify the SDK request before invoking its tools");
    };
    assert_eq!(model_request.action_class, "communication.external.send");
    assert!(matches!(
        table.find_match(
            &Method::POST,
            &Authority::from_static("unlisted.example.com"),
            "/v1/responses"
        ),
        MatchResult::UnclassifiedProtected
    ));
}

#[test]
fn catalog_consumer_rejects_schema_drift_unknown_fields_and_duplicate_ids() {
    let unsupported = CORPUS.replacen("schema_version = 1", "schema_version = 2", 1);
    assert!(decode_corpus(&unsupported).is_err());

    let unknown = CORPUS.replacen(
        "schema_version = 1",
        "schema_version = 1\nunknown = true",
        1,
    );
    assert!(decode_corpus(&unknown).is_err());

    let unknown_case = CORPUS.replacen(
        "id = \"parse-minimal-rule\"",
        "id = \"parse-minimal-rule\"\nunknown = true",
        1,
    );
    assert!(decode_corpus(&unknown_case).is_err());

    let unknown_catalog = CORPUS.replacen(
        "selection = \"anthropic\"",
        "selection = \"anthropic\"\nunknown = true",
        1,
    );
    assert!(decode_corpus(&unknown_catalog).is_err());

    let unknown_catalog_host = CORPUS.replacen(
        "subdomain = \"*\", rule_count = 2 }",
        "subdomain = \"*\", rule_count = 2, unknown = true }",
        1,
    );
    assert!(decode_corpus(&unknown_catalog_host).is_err());

    let duplicate = CORPUS.replacen(
        "id = \"normalize-root-path\"",
        "id = \"parse-minimal-rule\"",
        1,
    );
    assert!(decode_corpus(&duplicate).is_err());
}
