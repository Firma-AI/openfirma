//! Loads and validates pinned Composio source snapshots and manual mappings.

use std::collections::{HashMap, HashSet};

use firma_core::ActionClass;
use serde::Deserialize;

/// A validated mapped Composio tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Toolkit identifier.
    pub toolkit: String,
    /// Pinned toolkit version.
    pub version: String,
    /// Manually reviewed semantic action class.
    pub action_class: String,
}

/// Reviewed catalog pairs compiled into the Sidecar.
///
/// Refreshing a toolkit is a maintenance operation, never a hot-path lookup:
/// regenerate the pair with `scripts/composio_catalog.py`, classify every new
/// slug, and rebuild.
const BUILTIN_PAIRS: [(&str, &str); 3] = [
    (
        include_str!("../../config/composio/gmail-20260721_00.json"),
        include_str!("../../config/composio/gmail-20260721_00.mapping.json"),
    ),
    (
        include_str!("../../config/composio/googlecalendar-20260721_00.json"),
        include_str!("../../config/composio/googlecalendar-20260721_00.mapping.json"),
    ),
    (
        include_str!("../../config/composio/slack-20260721_00.json"),
        include_str!("../../config/composio/slack-20260721_00.mapping.json"),
    ),
];

/// Validated pinned Composio catalogs indexed by exact tool slug.
#[derive(Debug, Clone)]
pub struct ComposioCatalogs {
    entries: HashMap<String, CatalogEntry>,
}

impl ComposioCatalogs {
    /// Load the reviewed catalogs shipped with the Sidecar.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] when a shipped snapshot and its mapping have
    /// drifted apart, which fails Sidecar startup rather than leaving Composio
    /// traffic unclassified.
    pub fn builtin() -> Result<Self, CatalogError> {
        Self::from_json_pairs(BUILTIN_PAIRS)
    }

    /// Load and validate source/mapping JSON pairs.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for malformed JSON, version drift, duplicate
    /// slugs, wrong toolkit prefixes, unknown classes, or incomplete mappings.
    pub fn from_json_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, CatalogError> {
        let mut entries = HashMap::new();
        for (source_json, mapping_json) in pairs {
            let source: CatalogSource =
                serde_json::from_str(source_json).map_err(|_| CatalogError::MalformedSource)?;
            let mapping: CatalogMapping =
                serde_json::from_str(mapping_json).map_err(|_| CatalogError::MalformedMapping)?;
            validate_pair(&source, &mapping)?;
            for tool in source.tools {
                let Some(action_class) = mapping.mappings.get(&tool.slug) else {
                    return Err(CatalogError::SourceMappingDifference);
                };
                let Some(action_class) = action_class else {
                    return Err(CatalogError::MissingMapping);
                };
                if entries
                    .insert(
                        tool.slug.clone(),
                        CatalogEntry {
                            toolkit: source.toolkit.clone(),
                            version: source.version.clone(),
                            action_class: action_class.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(CatalogError::DuplicateSlug);
                }
            }
        }
        Ok(Self { entries })
    }

    /// Return the reviewed entry for an exact tool slug.
    #[must_use]
    pub fn lookup(&self, slug: &str) -> Option<&CatalogEntry> {
        self.entries.get(slug)
    }

    /// Return the number of reviewed tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether no tools were loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Pinned catalog validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// Source JSON could not be decoded.
    #[error("malformed Composio catalog source")]
    MalformedSource,
    /// Mapping JSON could not be decoded.
    #[error("malformed Composio catalog mapping")]
    MalformedMapping,
    /// Source and mapping identify different toolkit versions.
    #[error("Composio catalog source and mapping versions differ")]
    VersionMismatch,
    /// A source contains a duplicate slug.
    #[error("Composio catalog contains a duplicate tool slug")]
    DuplicateSlug,
    /// A slug does not use its toolkit prefix.
    #[error("Composio catalog tool has the wrong toolkit prefix")]
    WrongToolkitPrefix,
    /// A tool repeats mismatched toolkit or version metadata.
    #[error("Composio catalog tool metadata differs from its source")]
    ToolMetadataMismatch,
    /// A mapping names a non-canonical class.
    #[error("Composio catalog mapping uses an unknown action class")]
    UnknownActionClass,
    /// A mapping was left unclassified.
    #[error("Composio catalog contains an unmapped tool")]
    MissingMapping,
    /// Source and mapping slug sets differ.
    #[error("Composio catalog source and mapping slug sets differ")]
    SourceMappingDifference,
}

#[derive(Debug, Deserialize)]
struct CatalogSource {
    toolkit: String,
    version: String,
    tools: Vec<SourceTool>,
}

#[derive(Debug, Deserialize)]
struct SourceTool {
    toolkit: String,
    version: String,
    slug: String,
    #[serde(rename = "name")]
    _name: String,
    #[serde(rename = "description")]
    _description: String,
}

#[derive(Debug, Deserialize)]
struct CatalogMapping {
    toolkit: String,
    version: String,
    mappings: HashMap<String, Option<String>>,
}

fn validate_pair(source: &CatalogSource, mapping: &CatalogMapping) -> Result<(), CatalogError> {
    if source.toolkit != mapping.toolkit || source.version != mapping.version {
        return Err(CatalogError::VersionMismatch);
    }
    let prefix = format!("{}_", source.toolkit.to_ascii_uppercase());
    let mut source_slugs = HashSet::with_capacity(source.tools.len());
    for tool in &source.tools {
        if tool.toolkit != source.toolkit || tool.version != source.version {
            return Err(CatalogError::ToolMetadataMismatch);
        }
        if !tool.slug.starts_with(&prefix) {
            return Err(CatalogError::WrongToolkitPrefix);
        }
        if !source_slugs.insert(tool.slug.as_str()) {
            return Err(CatalogError::DuplicateSlug);
        }
    }
    if source_slugs.len() != mapping.mappings.len()
        || !source_slugs
            .iter()
            .all(|slug| mapping.mappings.contains_key(*slug))
    {
        return Err(CatalogError::SourceMappingDifference);
    }
    for action_class in mapping.mappings.values() {
        let Some(action_class) = action_class else {
            return Err(CatalogError::MissingMapping);
        };
        action_class
            .parse::<ActionClass>()
            .map_err(|_| CatalogError::UnknownActionClass)?;
    }
    Ok(())
}
