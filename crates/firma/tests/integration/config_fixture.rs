use std::path::Path;

use serde::Serialize;

pub fn write_section(path: &Path, section: &str, config: &impl Serialize) -> anyhow::Result<()> {
    let mut document = toml::Table::new();
    document.insert(section.to_owned(), toml::Value::try_from(config)?);
    let text = toml::to_string(&document)?;
    firma_config_loader::FirmaConfig::parse(path, &text)?;
    std::fs::write(path, text)?;
    Ok(())
}
