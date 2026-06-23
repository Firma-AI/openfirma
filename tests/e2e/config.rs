use std::path::{Path, PathBuf};

use anyhow::Context;
use firma_sidecar::config::{MappingRuleConfig, MappingRulesFile};

pub fn append_policy_rule(cfg_dir: &Path, name: &str, rule: &str) -> Result<(), anyhow::Error> {
    let path = cfg_dir.join("policies").join(format!("{name}.cedar"));
    let mut current = if path.exists() {
        fs_err::read_to_string(&path)?
    } else {
        String::new()
    };
    current.push('\n');
    current.push_str(rule);
    current.push('\n');
    fs_err::write(&path, current)?;
    Ok(())
}

pub fn add_mapping_rules(
    cfg_dir: &Path,
    rules: Vec<MappingRuleConfig>,
) -> Result<(), anyhow::Error> {
    let rules_path = cfg_dir.join("mapping-rules.toml");
    let mut file: MappingRulesFile = if rules_path.exists() {
        let content = fs_err::read_to_string(&rules_path)?;
        toml::from_str(&content).with_context(|| format!("parse {}", rules_path.display()))?
    } else {
        MappingRulesFile::default()
    };

    file.rules.extend(rules);
    let content = toml::to_string(&file).context("serialize mapping rules")?;
    fs_err::write(&rules_path, content)?;
    Ok(())
}

pub fn issue_capability(
    cfg_dir: &Path,
    agent_id: &str,
    session_id: &str,
    action: &str,
    scope: &str,
    ttl_secs: u64,
) -> Result<PathBuf, anyhow::Error> {
    let config_path = cfg_dir.join("firma.toml");
    let seed_path = cfg_dir.join("capability-seed.toml");
    let output = std::process::Command::new(crate::firma_bin())
        .arg("authority")
        .args(["--config"])
        .arg(&config_path)
        .arg("issue")
        .args(["--agent-id", agent_id])
        .args(["--session-id", session_id])
        .args(["--action", action])
        .args(["--resource-scope", scope])
        .args(["--ttl-seconds", &ttl_secs.to_string()])
        .args(["--output"])
        .arg(&seed_path)
        .output()
        .with_context(|| "spawn firma authority issue")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("firma authority issue failed: {stderr}");
    }

    Ok(seed_path)
}
