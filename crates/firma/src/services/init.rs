//! Runner for `firma init` — scaffold a new agent config directory.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use dialoguer::theme::ColorfulTheme;
use minijinja::{Environment, context};

use crate::args::init::{InitArgs, Mapping, Posture};

struct CollectedInputs {
    name: String,
    posture: Posture,
    mappings: Vec<Mapping>,
    extra_hosts: Vec<String>,
    workspace: PathBuf,
}

static TPL_FIRMA_TOML: &str = include_str!("../../templates/firma.toml.j2");
static TPL_MAPPING_RULES: &str = include_str!("../../templates/mapping-rules.toml.j2");
static TPL_FIRMA_RUN: &str = include_str!("../../templates/firma-run.toml.j2");
static TPL_CEDAR_ISSUANCE: &str = include_str!("../../templates/issuance.cedar");

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
    if args.list_templates {
        return Ok(crate::services::policy::list());
    }

    let inputs = collect_inputs(args)?;
    let out = std::path::absolute(&args.output_dir)
        .with_context(|| format!("resolve path {}", args.output_dir.display()))?;

    let env = build_template_env()?;
    let files = generate_files(&env, &inputs)?;

    if args.dry_run {
        for (rel, content) in &files {
            println!("=== {} ===", out.join(rel).display());
            println!("{content}");
        }
        return Ok(ExitCode::SUCCESS);
    }

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

    for (rel, content) in &files {
        let path = out.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
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

    write_if_absent(&out.join(".runtime/revocations.txt"), b"", args.force)?;
    write_if_absent(
        &out.join(".runtime/audit.key"),
        DEMO_AUDIT_KEY_PEM.as_bytes(),
        args.force,
    )?;

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
    inputs: &CollectedInputs,
) -> Result<Vec<(String, String)>> {
    let mapping_paths: Vec<String> = inputs
        .mappings
        .iter()
        .map(|m| format!("mappings/{}.toml", m.as_str()))
        .collect();

    let mitm_hosts: Vec<&str> = inputs
        .mappings
        .iter()
        .flat_map(Mapping::mitm_hosts)
        .copied()
        .collect();

    let requested_actions = inputs.posture.requested_actions();
    let workspace_str = inputs.workspace.to_string_lossy();

    let firma_toml = render(
        env,
        "firma.toml",
        context! { name => inputs.name, mapping_paths, mitm_hosts, requested_actions },
    )?;
    let mapping_rules = render(
        env,
        "mapping-rules.toml",
        context! { extra_hosts => inputs.extra_hosts },
    )?;
    let firma_run = render(
        env,
        "firma-run.toml",
        context! { name => inputs.name, workspace => workspace_str.as_ref() },
    )?;

    let cedar_path = format!("policies/{}.cedar", inputs.posture.file_name());
    let mut files = vec![
        ("firma.toml".into(), firma_toml),
        ("mapping-rules.toml".into(), mapping_rules),
        (cedar_path, inputs.posture.cedar_content().to_string()),
        (
            "issuance-policies/issuance.cedar".into(),
            TPL_CEDAR_ISSUANCE.to_string(),
        ),
        ("firma-run.toml".into(), firma_run),
    ];

    for mapping in &inputs.mappings {
        files.push((
            format!("mappings/{}.toml", mapping.as_str()),
            mapping.static_content().to_string(),
        ));
    }

    Ok(files)
}

fn render(env: &Environment<'_>, template: &str, ctx: minijinja::Value) -> Result<String> {
    env.get_template(template)
        .and_then(|t| t.render(ctx))
        .with_context(|| format!("render template {template}"))
}

fn collect_inputs(args: &InitArgs) -> Result<CollectedInputs> {
    let name = resolve_or_prompt(args.name.as_deref(), "Agent name", "my-agent")?;

    let posture = match &args.posture {
        Some(p) => p.clone(),
        None => prompt_posture()?,
    };

    let mappings = if args.mapping.is_empty() {
        prompt_mappings()?
    } else {
        args.mapping.clone()
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
        std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()))?
    } else {
        let out_abs = std::path::absolute(&args.output_dir)
            .with_context(|| format!("resolve path {}", args.output_dir.display()))?;
        let default = out_abs.to_string_lossy().into_owned();
        let s = resolve_or_prompt(None, "Workspace directory (agent RW access)", &default)?;
        let p = PathBuf::from(s);
        std::path::absolute(&p).with_context(|| format!("resolve path {}", p.display()))?
    };

    Ok(CollectedInputs {
        name,
        posture,
        mappings,
        extra_hosts,
        workspace,
    })
}

fn prompt_posture() -> Result<Posture> {
    let items = &[
        "strict                  Default-deny + communication only",
        "dev                     Adds code.read/write, issues, package install",
        "dev-with-delete-watch   Dev + code.destructive allowed (local-exec)",
    ];
    let selection = dialoguer::Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Posture")
        .items(items)
        .default(1)
        .interact()
        .context("posture prompt")?;
    Ok(match selection {
        0 => Posture::Strict,
        1 => Posture::Dev,
        _ => Posture::DevWithDeleteWatch,
    })
}

fn prompt_mappings() -> Result<Vec<Mapping>> {
    let items = &[
        "anthropic   api.anthropic.com (CONNECT, no MITM)",
        "openai      api.openai.com (CONNECT, no MITM)",
        "github      api.github.com (MITM for per-endpoint classification)",
        "gmail       gmail.googleapis.com (MITM for per-endpoint classification)",
        "npm         registry.npmjs.org",
        "pypi        pypi.org, files.pythonhosted.org",
        "cargo       crates.io, static.crates.io",
        "stripe      api.stripe.com (MITM optional — check SDK cert pinning first)",
        "custom      Empty template — fill in manually",
    ];
    let defaults = &[true, false, false, false, false, false, false, false, false];
    let selections = dialoguer::MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Mappings (space to toggle, enter to confirm)")
        .items(items)
        .defaults(defaults)
        .interact()
        .context("mappings prompt")?;
    Ok(selections
        .into_iter()
        .filter_map(|i| {
            Some(match i {
                0 => Mapping::Anthropic,
                1 => Mapping::Openai,
                2 => Mapping::Github,
                3 => Mapping::Gmail,
                4 => Mapping::Npm,
                5 => Mapping::Pypi,
                6 => Mapping::Cargo,
                7 => Mapping::Stripe,
                8 => Mapping::Custom,
                _ => return None,
            })
        })
        .collect())
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

    fn make_files(
        posture: &Posture,
        mappings: &[Mapping],
        extra_hosts: &[String],
    ) -> Vec<(String, String)> {
        let env = build_template_env().unwrap();
        let inputs = CollectedInputs {
            name: TEST_AGENT.to_string(),
            posture: posture.clone(),
            mappings: mappings.to_vec(),
            extra_hosts: extra_hosts.to_vec(),
            workspace: PathBuf::from(TEST_WORKSPACE),
        };
        generate_files(&env, &inputs).unwrap()
    }

    fn get<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
        files.iter().find(|(k, _)| k == name).map_or_else(
            || panic!("file {name} not found in generated output"),
            |(_, v)| v.as_str(),
        )
    }

    fn parse_rules(content: &str) -> firma_sidecar::config::MappingRulesFile {
        toml::from_str(content).unwrap()
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    #[test]
    fn all_postures_render_without_error() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            make_files(&posture, &[], &[]);
        }
    }

    #[test]
    fn all_mappings_render_without_error() {
        let all_mappings = vec![
            Mapping::Anthropic,
            Mapping::Openai,
            Mapping::Github,
            Mapping::Gmail,
            Mapping::Npm,
            Mapping::Pypi,
            Mapping::Cargo,
            Mapping::Stripe,
            Mapping::Custom,
        ];
        make_files(&Posture::Dev, &all_mappings, &[]);
    }

    #[test]
    fn extra_hosts_render_without_error() {
        make_files(
            &Posture::Dev,
            &[Mapping::Anthropic],
            &["api.example.com".to_string()],
        );
    }

    // ── firma.toml ───────────────────────────────────────────────────────────

    #[test]
    fn firma_toml_is_valid_toml() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            let files = make_files(&posture, &[Mapping::Anthropic, Mapping::Github], &[]);
            let _: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        }
    }

    #[test]
    fn firma_toml_agent_id_matches_name() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        assert_eq!(
            t["sidecar"]["preflight"]["agent_id"].as_str(),
            Some(TEST_AGENT),
        );
    }

    #[test]
    fn firma_toml_parses_as_authority_config() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("firma.toml");
        std::fs::write(&path, get(&files, "firma.toml")).unwrap();
        let body = firma_config::load_section(&path, "authority").unwrap();
        let _: firma_authority::AuthorityConfig = toml::from_str(&body).unwrap();
    }

    #[test]
    fn firma_toml_parses_as_sidecar_config() {
        for posture in [Posture::Strict, Posture::Dev] {
            for mappings in [
                vec![],
                vec![Mapping::Anthropic],
                vec![Mapping::Github, Mapping::Gmail],
            ] {
                let files = make_files(&posture, &mappings, &[]);
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("firma.toml");
                std::fs::write(&path, get(&files, "firma.toml")).unwrap();
                let body = firma_config::load_section(&path, "sidecar").unwrap();
                let _: firma_sidecar::config::SidecarConfig = toml::from_str(&body).unwrap();
            }
        }
    }

    #[test]
    fn firma_toml_mitm_hosts_populated_for_github_gmail() {
        let files = make_files(
            &Posture::Dev,
            &[Mapping::Anthropic, Mapping::Github, Mapping::Gmail],
            &[],
        );
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        let hosts = t["sidecar"]["interceptor"]["https_mitm"]["intercept_hosts"]
            .as_array()
            .unwrap();
        let host_strs: Vec<_> = hosts.iter().filter_map(|v| v.as_str()).collect();
        assert!(host_strs.contains(&"api.github.com"));
        assert!(host_strs.contains(&"gmail.googleapis.com"));
        assert!(!host_strs.contains(&"api.anthropic.com"));
    }

    #[test]
    fn firma_toml_no_mitm_hosts_when_only_anthropic() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        let hosts = t["sidecar"]["interceptor"]["https_mitm"]["intercept_hosts"]
            .as_array()
            .unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn firma_toml_rules_paths_contains_selected_mappings() {
        let files = make_files(&Posture::Dev, &[Mapping::Anthropic, Mapping::Github], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma.toml")).unwrap();
        let paths = t["sidecar"]["mapping"]["rules_paths"].as_array().unwrap();
        let path_strs: Vec<_> = paths.iter().filter_map(|v| v.as_str()).collect();
        assert!(path_strs.contains(&"mappings/anthropic.toml"));
        assert!(path_strs.contains(&"mappings/github.toml"));
    }

    // ── mapping-rules.toml ───────────────────────────────────────────────────

    #[test]
    fn mapping_rules_is_valid_toml() {
        let files = make_files(&Posture::Dev, &[], &[]);
        parse_rules(get(&files, "mapping-rules.toml"));
    }

    #[test]
    fn mapping_rules_has_localhost_rules() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(rules.iter().any(|r| r.host.starts_with("localhost:")));
        assert!(rules.iter().any(|r| r.host.starts_with("127.0.0.1:")));
    }

    #[test]
    fn mapping_rules_no_llm_connect_rule_in_base() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        assert!(
            !rules.iter().any(|r| r.host == "api.anthropic.com:443"),
            "LLM rules must be in mappings/ not in mapping-rules.toml"
        );
        assert!(
            !rules.iter().any(|r| r.host == "api.openai.com:443"),
            "LLM rules must be in mappings/ not in mapping-rules.toml"
        );
    }

    #[test]
    fn mapping_rules_extra_hosts_produce_connect_and_wildcard_rules() {
        let extra = vec!["api.example.com".to_string()];
        let files = make_files(&Posture::Dev, &[], &extra);
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
        let files = make_files(&Posture::Dev, &[], &["extra.host.com".to_string()]);
        let rules = parse_rules(get(&files, "mapping-rules.toml")).rules;
        for rule in &rules {
            rule.validate()
                .unwrap_or_else(|e| panic!("invalid rule {:?}: {e}", rule.host));
        }
    }

    // ── Individual mapping files ──────────────────────────────────────────────

    #[test]
    fn anthropic_mapping_has_connect_rule() {
        let rules = parse_rules(Mapping::Anthropic.static_content()).rules;
        assert!(
            rules.iter().any(
                |r| r.host == "api.anthropic.com:443" && r.method.as_deref() == Some("CONNECT")
            ),
            "expected api.anthropic.com:443 CONNECT rule"
        );
    }

    #[test]
    fn openai_mapping_has_connect_rule() {
        let rules = parse_rules(Mapping::Openai.static_content()).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.openai.com:443" && r.method.as_deref() == Some("CONNECT")),
            "expected api.openai.com:443 CONNECT rule"
        );
    }

    #[test]
    fn github_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Github.static_content()).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.github.com:443" && r.method.as_deref() == Some("CONNECT")),
            "CONNECT rule missing from github mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.github.com" && r.path.is_some()),
            "REST rules missing from github mapping"
        );
    }

    #[test]
    fn gmail_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Gmail.static_content()).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "gmail.googleapis.com:443"
                    && r.method.as_deref() == Some("CONNECT")),
            "CONNECT rule missing from gmail mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "gmail.googleapis.com" && r.path.is_some()),
            "REST rules missing from gmail mapping"
        );
    }

    #[test]
    fn stripe_mapping_has_connect_and_rest_rules() {
        let rules = parse_rules(Mapping::Stripe.static_content()).rules;
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.stripe.com:443" && r.method.as_deref() == Some("CONNECT")),
            "CONNECT rule missing from stripe mapping"
        );
        assert!(
            rules
                .iter()
                .any(|r| r.host == "api.stripe.com" && r.path.is_some()),
            "REST rules missing from stripe mapping"
        );
    }

    #[test]
    fn all_mapping_files_parse_and_validate() {
        let all = [
            Mapping::Anthropic,
            Mapping::Openai,
            Mapping::Github,
            Mapping::Gmail,
            Mapping::Npm,
            Mapping::Pypi,
            Mapping::Cargo,
            Mapping::Stripe,
            Mapping::Custom,
        ];
        for m in &all {
            let f = parse_rules(m.static_content());
            for rule in &f.rules {
                rule.validate()
                    .unwrap_or_else(|e| panic!("invalid rule in {}: {e}", m.as_str()));
            }
        }
    }

    // ── firma-run.toml ───────────────────────────────────────────────────────

    #[test]
    fn firma_run_toml_is_valid_toml() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let _: toml::Value = toml::from_str(get(&files, "firma-run.toml")).unwrap();
    }

    #[test]
    fn firma_run_toml_workspace_mount_matches_input() {
        let files = make_files(&Posture::Dev, &[], &[]);
        let t: toml::Value = toml::from_str(get(&files, "firma-run.toml")).unwrap();
        let mounts = t["profiles"]["generic"]["mounts"].as_array().unwrap();
        assert_eq!(mounts[0]["source"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["target"].as_str(), Some(TEST_WORKSPACE));
        assert_eq!(mounts[0]["read_only"].as_bool(), Some(false));
    }

    // ── Cedar posture files ───────────────────────────────────────────────────

    #[test]
    fn cedar_file_named_after_posture() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            let files = make_files(&posture, &[], &[]);
            let expected = format!("policies/{}.cedar", posture.file_name());
            assert!(
                files.iter().any(|(k, _)| k == &expected),
                "expected {expected} in generated files for posture {posture:?}"
            );
        }
    }

    #[test]
    fn posture_cedar_files_are_non_empty() {
        for posture in [Posture::Strict, Posture::Dev, Posture::DevWithDeleteWatch] {
            assert!(!posture.cedar_content().is_empty());
        }
    }

    #[test]
    fn strict_posture_does_not_permit_code_write() {
        assert!(
            !Posture::Strict.cedar_content().contains("code.write"),
            "strict posture must not permit code.write"
        );
    }

    #[test]
    fn dev_with_delete_watch_does_not_forbid_code_destructive() {
        let content = Posture::DevWithDeleteWatch.cedar_content();
        let forbid_stanza =
            "forbid (\n    principal,\n    action == Firma::Action::\"code.destructive\"";
        assert!(
            !content.contains(forbid_stanza),
            "dev-with-delete-watch must not contain a forbid stanza for code.destructive"
        );
    }
}
