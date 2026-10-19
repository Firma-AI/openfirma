//! Admission of the managed effective mapping language, not authored set metadata.

use firma_http::Method;
use firma_protobuf::v1::ActionMappingSnapshot;

use crate::config::MappingRuleConfig;
use crate::normalizer::MappingTable;
use crate::normalizer::mapping::MappingTableError;

// Mirrors the producer's aggregate budget without depending on private Team code.
const MAX_SNAPSHOT_RULES: usize = 10_000;

pub(super) fn compile(snapshot: Option<&ActionMappingSnapshot>) -> Result<MappingTable, String> {
    let snapshot = snapshot.ok_or("managed policy bundle requires an action mapping snapshot")?;
    if snapshot.format_version != 1 || !snapshot.default_protected {
        return Err("mapping snapshot requires format version 1 and default_protected=true".into());
    }

    if snapshot.rules.len() > MAX_SNAPSHOT_RULES {
        return Err("mapping snapshot exceeds 10000 rules".into());
    }

    if snapshot.rules.is_empty() {
        return Ok(MappingTable::empty_protected());
    }

    let rules = snapshot
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let method = rule
                .method
                .as_deref()
                .map(|method| {
                    method
                        .parse::<Method>()
                        .map_err(|_| format!("mapping rule {index}: invalid method"))
                })
                .transpose()?;

            Ok(MappingRuleConfig {
                method,
                host: rule.host.clone(),
                path: rule.path.clone(),
                action_class: rule.action_class.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    // Host canonical form, path safety, method membership, duplicate tuples,
    // and action-class membership are enforced once by the managed table
    // constructor; method syntax above is the only proto-string conversion.
    MappingTable::from_managed_rules(rules).map_err(|error| describe(&error))
}

/// Identify a rejected rule without echoing its contents into a background
/// task's logs.
fn describe(error: &MappingTableError) -> String {
    match error {
        // Managed validation names the rule index and the violated property.
        MappingTableError::InvalidRulesFile(detail) => format!("mapping {detail}"),
        MappingTableError::DuplicateRule { index, .. } => {
            format!("mapping rule {index}: duplicate matcher")
        }
        MappingTableError::NonExistingActionClass { index, .. } => {
            format!("mapping rule {index}: unknown action class")
        }
    }
}
