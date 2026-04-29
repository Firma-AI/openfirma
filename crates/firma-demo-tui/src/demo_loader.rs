use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};

pub struct DemoEntry {
    pub name: String,
    pub path: PathBuf,
    pub tagline: String,
}

pub struct DemoManifest {
    pub root: PathBuf,
    pub description: String,
    pub authority_config: PathBuf,
    pub sidecar_config: PathBuf,
    pub agent_script: PathBuf,
    pub agent_prompt: String,
}

/// Scan a directory for demo subdirectories (any dir containing description.md).
pub fn discover(dir: &Path) -> Result<Vec<DemoEntry>> {
    let read_dir = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read demos directory: {}", dir.display()))?;

    let mut entries: Vec<DemoEntry> = read_dir
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("description.md").exists())
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            let tagline = std::fs::read_to_string(path.join("description.md"))
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("# ")).map_or_else(|| name.clone(), |l| l.trim_start_matches("# ").to_owned());

            DemoEntry {
                name,
                path,
                tagline,
            }
        })
        .collect();

    entries.sort_by(|a, b| a.name.cmp(&b.name));

    ensure!(!entries.is_empty(), "no demos found in {}", dir.display());

    Ok(entries)
}

/// Load and validate a demo directory into a `DemoManifest`.
pub fn load(dir: &Path) -> Result<DemoManifest> {
    let root = dir
        .canonicalize()
        .with_context(|| format!("demo directory not found: {}", dir.display()))?;

    let description = read_required(&root, "description.md")?;
    let authority_config = required_path(&root, "authority.toml")?;
    let sidecar_config = required_path(&root, "sidecar.toml")?;
    let agent_script = required_path(&root, "agent.py")?;
    let agent_prompt = read_required(&root, "agent_prompt.md")?;

    Ok(DemoManifest {
        root,
        description,
        authority_config,
        sidecar_config,
        agent_script,
        agent_prompt,
    })
}

fn required_path(root: &Path, file: &str) -> Result<PathBuf> {
    let path = root.join(file);
    ensure!(path.exists(), "missing {file} in {}", root.display());
    Ok(path)
}

fn read_required(root: &Path, file: &str) -> Result<String> {
    let path = root.join(file);
    std::fs::read_to_string(&path).with_context(|| format!("missing {file} in {}", root.display()))
}
