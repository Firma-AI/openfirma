use std::path::{Path, PathBuf};

use anyhow::Context;

// ── Policy files ──────────────────────────────────────────────────────────────

pub fn append_policy_rule(cfg_dir: &Path, name: &str, rule: &str) -> Result<(), anyhow::Error> {
    let path = cfg_dir.join("policies").join(format!("{name}.cedar"));
    let mut current = std::fs::read_to_string(&path)
        .with_context(|| format!("read policy {}", path.display()))?;
    current.push('\n');
    current.push_str(rule);
    current.push('\n');
    std::fs::write(&path, current).with_context(|| format!("append policy {}", path.display()))?;
    Ok(())
}

// ── Mapping rules ──────────────────────────────────────────────────────────────

pub fn add_mapping_rule(
    cfg_dir: &Path,
    host: &str,
    method: &str,
    path: &str,
    action_class: &str,
) -> Result<(), anyhow::Error> {
    let rules_path = cfg_dir.join("mapping-rules.toml");
    if rules_path.exists() {
        let content = std::fs::read_to_string(&rules_path)
            .with_context(|| format!("read {}", rules_path.display()))?;
        let mut doc: toml_edit::DocumentMut = content
            .parse()
            .with_context(|| format!("parse {}", rules_path.display()))?;

        let rules = doc["rules"].or_insert(toml_edit::array());
        let mut table = toml_edit::Table::new();
        table.insert("method", toml_edit::value(method));
        table.insert("host", toml_edit::value(host));
        table.insert("path", toml_edit::value(path));
        table.insert("action_class", toml_edit::value(action_class));
        rules
            .as_array_of_tables_mut()
            .ok_or_else(|| anyhow::anyhow!("[rules] is not an array of tables"))?
            .push(table);

        std::fs::write(&rules_path, doc.to_string())
            .with_context(|| format!("write {}", rules_path.display()))?;
    } else {
        let content = format!(
            "[[rules]]\nmethod = \"{method}\"\nhost = \"{host}\"\npath = \"{path}\"\naction_class = \"{action_class}\"\n"
        );
        std::fs::write(&rules_path, content)
            .with_context(|| format!("create {}", rules_path.display()))?;
    }
    Ok(())
}

// ── firma.toml edits ───────────────────────────────────────────────────────────

pub fn set_config_value(cfg_dir: &Path, key: &str, value: &str) -> Result<(), anyhow::Error> {
    let path = cfg_dir.join("firma.toml");
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = content
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;

    let parts: Vec<&str> = key.split('.').collect();
    let mut current = doc.as_table_mut();
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            current.insert(part, toml_edit::value(value));
        } else {
            current = current[part]
                .or_insert(toml_edit::table())
                .as_table_mut()
                .ok_or_else(|| anyhow::anyhow!("key segment '{part}' is not a table"))?;
        }
    }

    std::fs::write(&path, doc.to_string()).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// ── Capability issuance ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn issue_capability(
    firma_bin: &Path,
    _state_dir: &Path,
    cfg_dir: &Path,
    agent_id: &str,
    session_id: &str,
    action: &str,
    scope: &str,
    ttl_secs: u64,
) -> Result<PathBuf, anyhow::Error> {
    let config_path = cfg_dir.join("firma.toml");
    let seed_path = cfg_dir.join("capability-seed.toml");
    let output = std::process::Command::new(firma_bin)
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

// ── Audit ──────────────────────────────────────────────────────────────────────

pub fn configure_audit_path(cfg_dir: &Path, audit_path: &Path) -> Result<(), anyhow::Error> {
    set_config_value(
        cfg_dir,
        "sidecar.audit.file_path",
        &audit_path.to_string_lossy(),
    )
}
