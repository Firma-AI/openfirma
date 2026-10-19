//! Converts authored mapping files into the canonical snapshot language.
//!
//! Authored files keep the forgiving grammar recorded by the mapping
//! compatibility corpus: unknown fields are ignored, and `path = ""` duplicates
//! an omitted path but matches no request. The published snapshot is canonical,
//! so neither leniency reaches the wire: an empty-path rule is validated and
//! then left out instead of being widened to every path.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail, ensure};
use firma_core::normalize_mapping_host;
use firma_protobuf::v1::{ActionMappingRule, ActionMappingSnapshot};
use serde::Deserialize;

/// Upper bound on the number of rules in one published snapshot.
const MAX_RULES: usize = 10_000;

#[derive(Deserialize)]
struct MappingFile {
    #[serde(default)]
    rules: Vec<AuthoredRule>,
}

#[derive(Deserialize)]
struct AuthoredRule {
    method: Option<String>,
    host: String,
    path: Option<String>,
    action_class: String,
}

pub fn load(paths: &[PathBuf]) -> Result<ActionMappingSnapshot> {
    let mut rules = Vec::new();
    let mut seen = HashMap::new();
    for path in paths {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read mapping rules {}", path.display()))?;
        let file: MappingFile = toml::from_str(&text)
            .with_context(|| format!("parse mapping rules {}", path.display()))?;
        for (index, authored) in file.rules.into_iter().enumerate() {
            ensure!(
                rules.len() < MAX_RULES,
                "mapping snapshot exceeds {MAX_RULES} rules"
            );
            let location = format!("{} rule {index}", path.display());
            let matches_nothing = authored.path.as_deref() == Some("");
            let rule = canonical_rule(authored).with_context(|| location.clone())?;
            let matcher = (rule.method.clone(), rule.host.clone(), rule.path.clone());
            if let Some(first) = seen.insert(matcher, location.clone()) {
                bail!("{location}: duplicate mapping matcher (first defined at {first})");
            }
            if matches_nothing {
                tracing::warn!(
                    rule = %location,
                    "mapping rule with an empty path matches no request; omit the path to match every path"
                );
                continue;
            }
            rules.push(rule);
        }
    }
    Ok(ActionMappingSnapshot {
        format_version: 1,
        default_protected: true,
        rules,
    })
}

fn canonical_rule(authored: AuthoredRule) -> Result<ActionMappingRule> {
    let written = authored.host.trim();
    firma_core::mapping::validate_authored_mapping_host(written).map_err(anyhow::Error::msg)?;
    let host = normalize_mapping_host(written);
    let path = authored.path.filter(|path| !path.is_empty());
    firma_core::mapping::validate_managed_rule(
        authored.method.as_deref(),
        &host,
        path.as_deref(),
        &authored.action_class,
    )?;
    Ok(ActionMappingRule {
        method: authored.method,
        host,
        path,
        action_class: authored.action_class,
    })
}
