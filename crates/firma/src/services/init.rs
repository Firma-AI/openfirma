//! Runner for `firma init` — scaffold a new agent config directory.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use minijinja::{Environment, context};

use crate::args::init::{InitArgs, Provider};

// Static templates embedded at compile time.
static TPL_FIRMA_TOML: &str = include_str!("../../templates/firma.toml.j2");
static TPL_MAPPING_RULES: &str = include_str!("../../templates/mapping-rules.toml.j2");
static TPL_FIRMA_RUN: &str = include_str!("../../templates/firma-run.toml.j2");
static TPL_CEDAR_POLICY: &str = include_str!("../../templates/llm-agent.cedar");
static TPL_CEDAR_ISSUANCE: &str = include_str!("../../templates/issuance.cedar");
static TPL_GITHUB_MAPPINGS: &str = include_str!("../../templates/github.toml");
static TPL_GMAIL_MAPPINGS: &str = include_str!("../../templates/gmail.toml");

// Same demo key used by `firma stack init`; not for production use.
const DEMO_AUDIT_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS+9b9zHd22EAeg9M
bXfQcvk+kh+UDhxsRkIm8BsBd4ihRANCAARrNl5iPKSasLwfIihEcv8BeQsqAXMl
3wlh7RZmOnI0E3wNCaMKd3B7Sd/fXknJ0WmI6BsrvfidxQEAYvsndbvx
-----END PRIVATE KEY-----
";

/// Entry point for `firma init`.
///
/// # Errors
///
/// Returns an error on I/O failure or template-rendering failure.
pub fn run(args: &InitArgs) -> Result<ExitCode> {
    let (name, provider, extra_hosts, workspace) = collect_inputs(args)?;
    let out = absolutize(&args.output_dir)?;

    let env = build_template_env()?;
    let files = generate_files(&env, &name, &provider, &extra_hosts, &workspace)?;

    if args.dry_run {
        for (rel, content) in &files {
            println!("=== {} ===", out.join(rel).display());
            println!("{content}");
        }
        return Ok(ExitCode::SUCCESS);
    }

    // Create directory tree.
    for sub in &[
        "policies",
        "issuance-policies",
        "mappings",
        ".runtime",
        ".runtime/generated-firma-ca",
    ] {
        let dir = out.join(sub);
        std::fs::create_dir_all(&dir).with_context(|| format!("mkdir {}", dir.display()))?;
    }

    // Write config files.
    for (rel, content) in &files {
        let path = out.join(rel);
        if !args.force && path.exists() {
            eprintln!(
                "skip (exists): {} — use --force to overwrite",
                path.display()
            );
            continue;
        }
        std::fs::write(&path, content.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        println!("  wrote {}", path.display());
    }

    // Empty revocations file.
    write_if_absent(&out.join(".runtime/revocations.txt"), b"", args.force)?;

    // Demo audit signing key.
    write_if_absent(
        &out.join(".runtime/audit.key"),
        DEMO_AUDIT_KEY_PEM.as_bytes(),
        args.force,
    )?;

    // Authority keypair (PASETO v4 asymmetric).
    let key_path = out.join(".runtime/authority.key");
    if args.force && key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| format!("remove {}", key_path.display()))?;
        let pub_path = out.join(".runtime/authority.pub");
        if pub_path.exists() {
            std::fs::remove_file(&pub_path)
                .with_context(|| format!("remove {}", pub_path.display()))?;
        }
    }
    if key_path.exists() {
        println!("  preserved existing authority keypair");
    } else {
        crate::services::authority::run_generate_key(&key_path)
            .with_context(|| format!("generate authority key at {}", key_path.display()))?;
        println!("  generated authority keypair → {}", key_path.display());
    }

    println!("\nAgent scaffolded: {}", out.display());
    println!("\nNext:");
    println!("  cd {}", out.display());
    println!("  firma stack start --config firma.toml");
    println!("  # In a separate terminal:");
    println!("  firma run --config firma-run.toml -- <agent-command>");

    Ok(ExitCode::SUCCESS)
}

fn build_template_env() -> Result<Environment<'static>> {
    let mut env = Environment::new();
    env.add_template("firma.toml", TPL_FIRMA_TOML)
        .context("load firma.toml template")?;
    env.add_template("mapping-rules.toml", TPL_MAPPING_RULES)
        .context("load mapping-rules.toml template")?;
    env.add_template("firma-run.toml", TPL_FIRMA_RUN)
        .context("load firma-run.toml template")?;
    Ok(env)
}

fn generate_files(
    env: &Environment<'_>,
    name: &str,
    provider: &Provider,
    extra_hosts: &[String],
    workspace: &Path,
) -> Result<Vec<(String, String)>> {
    let provider_str = match provider {
        Provider::Anthropic => "anthropic",
        Provider::Openai => "openai",
        Provider::Other => "other",
    };
    let workspace_str = workspace.to_string_lossy();

    let firma_toml = render(env, "firma.toml", context! { name })?;
    let mapping_rules = render(
        env,
        "mapping-rules.toml",
        context! { provider => provider_str, extra_hosts },
    )?;
    let firma_run = render(
        env,
        "firma-run.toml",
        context! { name, workspace => workspace_str },
    )?;

    Ok(vec![
        ("firma.toml".into(), firma_toml),
        ("mapping-rules.toml".into(), mapping_rules),
        (
            "policies/llm-agent.cedar".into(),
            TPL_CEDAR_POLICY.to_string(),
        ),
        (
            "issuance-policies/issuance.cedar".into(),
            TPL_CEDAR_ISSUANCE.to_string(),
        ),
        ("firma-run.toml".into(), firma_run),
        (
            "mappings/github.toml".into(),
            TPL_GITHUB_MAPPINGS.to_string(),
        ),
        ("mappings/gmail.toml".into(), TPL_GMAIL_MAPPINGS.to_string()),
    ])
}

fn render(env: &Environment<'_>, template: &str, ctx: minijinja::Value) -> Result<String> {
    env.get_template(template)
        .and_then(|t| t.render(ctx))
        .with_context(|| format!("render template {template}"))
}

fn collect_inputs(args: &InitArgs) -> Result<(String, Provider, Vec<String>, PathBuf)> {
    let name = resolve_or_prompt(args.name.as_deref(), "Agent name", "my-agent")?;

    let provider = match &args.provider {
        Some(p) => p.clone(),
        None => prompt_provider()?,
    };

    let extra_hosts_raw = resolve_or_prompt(
        args.extra_hosts.as_deref(),
        "Extra hosts (comma-separated, blank for none)",
        "",
    )?;
    let extra_hosts: Vec<String> = extra_hosts_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let workspace = if let Some(p) = &args.workspace {
        absolutize(p)?
    } else {
        let out_abs = absolutize(&args.output_dir)?;
        let default = out_abs.to_string_lossy().into_owned();
        let s = resolve_or_prompt(None, "Workspace directory (agent RW access)", &default)?;
        absolutize(&PathBuf::from(s))?
    };

    Ok((name, provider, extra_hosts, workspace))
}

fn resolve_or_prompt(value: Option<&str>, label: &str, default: &str) -> Result<String> {
    if let Some(v) = value {
        return Ok(v.to_string());
    }
    if default.is_empty() {
        print!("{label} (blank for none): ");
    } else {
        print!("{label} [{default}]: ");
    }
    std::io::stdout().flush().context("flush stdout")?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("read stdin")?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_provider() -> Result<Provider> {
    println!("LLM provider:");
    println!("  1) anthropic  (api.anthropic.com)");
    println!("  2) openai     (api.openai.com)");
    println!("  3) other      (add manually)");
    let choice = resolve_or_prompt(None, "Provider", "1")?;
    match choice.trim() {
        "1" | "anthropic" => Ok(Provider::Anthropic),
        "2" | "openai" => Ok(Provider::Openai),
        "3" | "other" => Ok(Provider::Other),
        other => anyhow::bail!("unknown provider: {other:?} — expected 1, 2, or 3"),
    }
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).with_context(|| format!("resolve path {}", path.display()))
}

fn write_if_absent(path: &Path, content: &[u8], force: bool) -> Result<()> {
    if !force && path.exists() {
        return Ok(());
    }
    std::fs::write(path, content).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const TEST_AGENT: &str = "test-agent";
    const TEST_WORKSPACE: &str = "/tmp/test-workspace";

    fn make_files(provider: &Provider, extra_hosts: &[String]) -> Vec<(String, String)> {
        let env = build_template_env().unwrap();
        generate_files(
            &env,
            TEST_AGENT,
            provider,
            extra_hosts,
            Path::new(TEST_WORKSPACE),
        )
        .unwrap()
    }

    fn get<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
        files.iter().find(|(k, _)| k == name).map_or_else(
            || panic!("file {name} not found in generated output"),
            |(_, v)| v.as_str(),
        )
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    #[test]
    fn all_providers_render_without_error() {
        for provider in [Provider::Anthropic, Provider::Openai, Provider::Other] {
            make_files(&provider, &[]);
        }
    }

    #[test]
    fn extra_hosts_render_without_error() {
        make_files(
            &Provider::Anthropic,
            &["api.example.com".to_string(), "cdn.example.com".to_string()],
        );
    }

    // ── firma.toml ───────────────────────────────────────────────────────────

    #[test]
    fn firma_toml_is_valid_toml() {
        let files = make_files(&Provider::Anthropic, &[]);
        let content = get(&files, "firma.toml");
        let _: toml::Value = toml::from_str(content).unwrap();
    }

    #[test]
    fn firma_toml_agent_id_matches_name() {
        let files = make_files(&Provider::Anthropic, &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        assert_eq!(
            t["sidecar"]["preflight"]["agent_id"].as_str(),
            Some(TEST_AGENT),
        );
    }

    #[test]
    fn firma_toml_parses_as_authority_config() {
        let files = make_files(&Provider::Anthropic, &[]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firma.toml");
        std::fs::write(&path, get(&files, "firma.toml")).unwrap();
        let body = firma_config::load_section(&path, "authority").unwrap();
        let _: firma_authority::AuthorityConfig = toml::from_str(&body).unwrap();
    }

    #[test]
    fn firma_toml_parses_as_sidecar_config() {
        let files = make_files(&Provider::Anthropic, &[]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firma.toml");
        std::fs::write(&path, get(&files, "firma.toml")).unwrap();
        let body = firma_config::load_section(&path, "sidecar").unwrap();
        let _: firma_sidecar::config::SidecarConfig = toml::from_str(&body).unwrap();
    }

    // ── mapping-rules.toml ───────────────────────────────────────────────────

    fn parse_rules(content: &str) -> firma_sidecar::config::MappingRulesFile {
        toml::from_str(content).unwrap()
    }

    #[test]
    fn mapping_rules_anthropic_is_valid_toml() {
        let files = make_files(&Provider::Anthropic, &[]);
        parse_rules(get(&files, "mapping-rules.toml"));
    }

    #[test]
    fn mapping_rules_openai_is_valid_toml() {
        let files = make_files(&Provider::Openai, &[]);
        parse_rules(get(&files, "mapping-rules.toml"));
    }

    #[test]
    fn mapping_rules_other_is_valid_toml() {
        let files = make_files(&Provider::Other, &[]);
        parse_rules(get(&files, "mapping-rules.toml"));
    }

    #[test]
    fn mapping_rules_anthropic_has_correct_llm_host() {
        let files = make_files(&Provider::Anthropic, &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            rules.iter().any(|r| r.host == "api.anthropic.com:443"),
            "expected api.anthropic.com:443 CONNECT rule"
        );
        assert!(
            !rules.iter().any(|r| r.host == "api.openai.com:443"),
            "openai rule must not appear for anthropic provider"
        );
    }

    #[test]
    fn mapping_rules_openai_has_correct_llm_host() {
        let files = make_files(&Provider::Openai, &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            rules.iter().any(|r| r.host == "api.openai.com:443"),
            "expected api.openai.com:443 CONNECT rule"
        );
        assert!(
            !rules.iter().any(|r| r.host == "api.anthropic.com:443"),
            "anthropic rule must not appear for openai provider"
        );
    }

    #[test]
    fn mapping_rules_other_has_no_llm_connect_rule() {
        let files = make_files(&Provider::Other, &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            !rules.iter().any(|r| r.host == "api.anthropic.com:443"),
            "anthropic rule must not appear for other provider"
        );
        assert!(
            !rules.iter().any(|r| r.host == "api.openai.com:443"),
            "openai rule must not appear for other provider"
        );
    }

    #[test]
    fn mapping_rules_extra_hosts_produce_connect_and_wildcard_rules() {
        let extra = vec!["api.example.com".to_string()];
        let files = make_files(&Provider::Anthropic, &extra);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.example.com:443" && r.method.as_deref() == Some("CONNECT")),
            "CONNECT rule for extra host missing"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.example.com" && r.path.as_deref() == Some("*")),
            "wildcard GET rule for extra host missing"
        );
    }

    #[test]
    fn mapping_rules_all_rules_pass_validation() {
        for provider in [Provider::Anthropic, Provider::Openai, Provider::Other] {
            let files = make_files(&provider, &["extra.host.com".to_string()]);
            let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
            for rule in &rules {
                rule.validate()
                    .unwrap_or_else(|e| panic!("invalid rule {:?}: {e}", rule.host));
            }
        }
    }

    // ── firma-run.toml ───────────────────────────────────────────────────────

    #[test]
    fn firma_run_toml_is_valid_toml() {
        let files = make_files(&Provider::Anthropic, &[]);
        let _: toml::Value = toml::from_str(get(&files, "firma-run.toml")).unwrap();
    }

    #[test]
    fn firma_run_toml_workspace_mount_matches_input() {
        let files = make_files(&Provider::Anthropic, &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma-run.toml")).unwrap();
        let mounts = t["profiles"]["generic"]["mounts"].as_array().unwrap();
        assert_eq!(mounts[0]["source"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["target"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["read_only"].as_bool(), Some(false));
    }

    // ── Static mapping files ──────────────────────────────────────────────────

    #[test]
    fn github_mappings_are_valid_toml_with_rules() {
        let files = make_files(&Provider::Anthropic, &[]);
        let f = parse_rules(get(&files, "mappings/github.toml"));
        assert!(
            !f.rules.is_empty(),
            "github.toml must have at least one rule"
        );
        for rule in &f.rules {
            rule.validate()
                .unwrap_or_else(|e| panic!("invalid github rule {:?}: {e}", rule.host));
        }
    }

    #[test]
    fn gmail_mappings_are_valid_toml_with_rules() {
        let files = make_files(&Provider::Anthropic, &[]);
        let f = parse_rules(get(&files, "mappings/gmail.toml"));
        assert!(
            !f.rules.is_empty(),
            "gmail.toml must have at least one rule"
        );
        for rule in &f.rules {
            rule.validate()
                .unwrap_or_else(|e| panic!("invalid gmail rule {:?}: {e}", rule.host));
        }
    }
}
