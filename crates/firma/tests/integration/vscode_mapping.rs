//! End-to-end classification coverage for the shipped vscode mapping
//! template, exercised through the sidecar's real `MappingTable`.

use firma_http::Method;
use firma_sidecar::config::MappingRulesFile;
use firma_sidecar::enforcement::registry::ActionClassRegistry;
use firma_sidecar::normalizer::{MappingTable, MatchResult};

/// The vscode mapping template scaffolded by `firma config --profile vscode`.
const VSCODE_MAPPING: &str = include_str!("../../templates/mappings/vscode.toml");

#[test]
fn vscode_mapping_classifies_copilot_chat_connect() {
    let file: MappingRulesFile =
        toml::from_str(VSCODE_MAPPING).unwrap_or_else(|e| panic!("vscode mapping must parse: {e}"));
    let table = MappingTable::from_config(&file, &ActionClassRegistry::v0_1(), true)
        .unwrap_or_else(|e| panic!("vscode mapping must build a table: {e}"));

    match table.find_match(&Method::CONNECT, "api.individual.githubcopilot.com", "/") {
        MatchResult::Matched(rule) => {
            assert_eq!(rule.action_class, "communication.external.send");
        }
        other => panic!("expected Copilot chat host to match a rule, got {other:?}"),
    }
}
