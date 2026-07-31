use std::fs;

use anyhow::Context as _;
use guppy::graph::PackageGraph;

pub fn load() -> Result<PackageGraph, anyhow::Error> {
    let metadata_path = std::env::var("FIRMA_ARCHITECTURE_METADATA")
        .context("FIRMA_ARCHITECTURE_METADATA is not set; run architecture tests with nextest")?;
    let metadata = fs::read_to_string(&metadata_path)
        .with_context(|| format!("failed to read cargo metadata from {metadata_path}"))?;

    PackageGraph::from_json(&metadata).context("failed to deserialize cargo metadata")
}
