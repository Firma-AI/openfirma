use anyhow::{Context, Result, ensure};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct DemoEntry {
    pub name: String,
    pub path: PathBuf,
    pub tagline: String,
    pub description: String,
}

pub struct DemoManifest {
    pub root: PathBuf,
    /// The single unified `firma.toml` for this demo (sectioned with
    /// `[authority]` and `[sidecar.*]`).
    pub config_file: PathBuf,
    pub agent_script: PathBuf,
    pub session_id: String,
    /// Human-readable description of what the script will do, shown in
    /// the agent pane before the user presses Enter to start. Loaded
    /// from `prompt.md` in the demo directory; empty if absent.
    pub prompt: String,
}

#[derive(Clone, Debug)]
pub struct ConfigItem {
    pub key: String,
    pub value: String,
    pub description: String,
}

/// Load the .env.sample as a template for dynamic configuration.
/// Populates with values from .env if it exists.
pub fn load_config_template(dir: &Path) -> Vec<ConfigItem> {
    let sample_path = dir.join(".env.sample");
    let env_path = dir.join(".env");

    let Ok(sample_content) = std::fs::read_to_string(&sample_path) else {
        return Vec::new();
    };

    // Load actual .env values if they exist
    let mut env_values = HashMap::new();
    if let Ok(env_content) = std::fs::read_to_string(&env_path) {
        for line in env_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                env_values.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    let mut items = Vec::new();
    let mut current_description = Vec::new();

    for line in sample_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('#') {
            current_description.push(line.trim_start_matches('#').trim().to_string());
            continue;
        }

        if let Some((key, _)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = env_values.get(&key).cloned().unwrap_or_default();
            items.push(ConfigItem {
                key,
                value,
                description: current_description.join(" "),
            });
            current_description.clear();
        }
    }

    items
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

            let description =
                std::fs::read_to_string(path.join("description.md")).unwrap_or_default();

            let tagline = description
                .lines()
                .find(|l| l.starts_with("# "))
                .map_or_else(|| name.clone(), |l| l.trim_start_matches("# ").to_owned());

            DemoEntry {
                name,
                path,
                tagline,
                description,
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

    let config_file = required_path(&root, "firma.toml")?;
    let agent_script = required_path(&root, "agent.py")?;
    let session_id = parse_preflight_session_id(&config_file);
    let prompt = std::fs::read_to_string(root.join("prompt.md")).unwrap_or_default();

    Ok(DemoManifest {
        root,
        config_file,
        agent_script,
        session_id,
        prompt,
    })
}

/// Extract `session_id` from the `[sidecar.preflight]` section of the
/// unified `firma.toml`.
fn parse_preflight_session_id(firma_toml: &Path) -> String {
    #[derive(serde::Deserialize)]
    struct FirmaToml {
        sidecar: Option<SidecarSection>,
    }
    #[derive(serde::Deserialize)]
    struct SidecarSection {
        preflight: Option<PreflightSection>,
    }
    #[derive(serde::Deserialize)]
    struct PreflightSection {
        session_id: Option<String>,
    }

    let Ok(content) = std::fs::read_to_string(firma_toml) else {
        return String::new();
    };
    toml::from_str::<FirmaToml>(&content)
        .ok()
        .and_then(|t| t.sidecar)
        .and_then(|s| s.preflight)
        .and_then(|p| p.session_id)
        .unwrap_or_default()
}

fn required_path(root: &Path, file: &str) -> Result<PathBuf> {
    let path = root.join(file);
    ensure!(path.exists(), "missing {file} in {}", root.display());
    Ok(path)
}
