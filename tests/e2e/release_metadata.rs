use std::fs;

use anyhow::Context as _;
use guppy::MetadataCommand;

#[test]
fn changelog_include_matches_workspace_packages() -> Result<(), anyhow::Error> {
    let graph = MetadataCommand::new().build_graph()?;
    let workspace = graph.workspace();
    let workspace_root = workspace.root();
    let config_source = fs::read_to_string(workspace_root.join(".release-plz.toml"))?;
    let config: toml::Value = toml::from_str(&config_source)?;
    let packages = config
        .get("package")
        .and_then(toml::Value::as_array)
        .context(".release-plz.toml has no [[package]] entries")?;
    let firma = packages
        .iter()
        .find(|package| package.get("name").and_then(toml::Value::as_str) == Some("firma"))
        .context(".release-plz.toml has no [[package]] entry for firma")?;
    let mut included = firma
        .get("changelog_include")
        .and_then(toml::Value::as_array)
        .context("firma has no changelog_include list")?
        .iter()
        .map(|package| {
            package
                .as_str()
                .map(ToOwned::to_owned)
                .context("changelog_include contains a non-string entry")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut expected = workspace
        .iter()
        .map(|package| package.name().to_owned())
        .filter(|package| package != "firma")
        .collect::<Vec<_>>();

    included.sort();
    expected.sort();
    assert_eq!(included, expected);
    Ok(())
}
