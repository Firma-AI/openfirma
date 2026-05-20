//! Runner for `firma init` — scaffold a new agent config directory.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::ValueEnum as _;
use dialoguer::theme::ColorfulTheme;
use minijinja::{Environment, context};

use crate::args::init::{InitArgs, Mapping, Posture};

struct CollectedInputs {
    name: String,
    posture: Posture,
    mappings: Vec<Mapping>,
    extra_hosts: Vec<String>,
    output_dir: PathBuf,
    workspace: PathBuf,
}

static TPL_FIRMA_TOML: &str = include_str!("../../templates/firma.toml.j2");
static TPL_MAPPING_RULES: &str = include_str!("../../templates/mapping-rules.toml.j2");
static TPL_FIRMA_RUN: &str = include_str!("../../templates/firma-run.toml.j2");
static TPL_CEDAR_ISSUANCE: &str = include_str!("../../templates/issuance.cedar");

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
    let out = &inputs.output_dir;

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
    crate::services::authority::generate_audit_key_if_absent(
        &out.join(".runtime/audit.key"),
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
    println!(
        "  firma run --config {}/firma-run.toml -- <agent-command>",
        out.display()
    );

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

fn default_output_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn global_config_dir() -> Result<PathBuf> {
    firma_config::default_config_dir(&firma_config::SystemDirs)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve global config dir (no home directory?)"))
}

fn collect_inputs(args: &InitArgs) -> Result<CollectedInputs> {
    let theme = ColorfulTheme::default();
    let interactive = !args.yes && dialoguer::console::Term::stderr().is_term();

    let name = match args.name.as_deref() {
        Some(v) => v.to_string(),
        None if interactive => dialoguer::Input::with_theme(&theme)
            .with_prompt("Agent name")
            .default("my-agent".to_string())
            .interact_text()
            .context("agent name prompt")?,
        None => "my-agent".to_string(),
    };

    let output_dir = if args.global {
        let p = global_config_dir()?;
        std::path::absolute(&p).with_context(|| format!("resolve path {}", p.display()))?
    } else {
        match &args.output_dir {
            Some(p) => {
                std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()))?
            }
            None if interactive => {
                let default = default_output_dir().to_string_lossy().into_owned();
                let s: String = dialoguer::Input::with_theme(&theme)
                    .with_prompt("Config directory")
                    .default(default)
                    .interact_text()
                    .context("config directory prompt")?;
                std::path::absolute(PathBuf::from(s)).context("resolve config directory path")?
            }
            None => default_output_dir(),
        }
    };

    let posture = match &args.posture {
        Some(p) => p.clone(),
        None if interactive => prompt_posture(&theme)?,
        None => Posture::Dev,
    };

    let mappings = if !args.mapping.is_empty() {
        args.mapping.clone()
    } else if interactive {
        prompt_mappings(&theme)?
    } else {
        vec![Mapping::Anthropic]
    };

    let extra_hosts_raw: String = match args.extra_hosts.as_deref() {
        Some(v) => v.to_string(),
        None if interactive => dialoguer::Input::with_theme(&theme)
            .with_prompt("Extra hosts (comma-separated, blank for none)")
            .allow_empty(true)
            .interact_text()
            .context("extra hosts prompt")?,
        None => String::new(), // default: no extra hosts
    };
    let extra_hosts: Vec<String> = extra_hosts_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let workspace = if let Some(p) = &args.workspace {
        std::path::absolute(p).with_context(|| format!("resolve path {}", p.display()))?
    } else {
        let cwd = std::env::current_dir().context("get current directory")?;
        if interactive {
            let default = cwd.to_string_lossy().into_owned();
            let s: String = dialoguer::Input::with_theme(&theme)
                .with_prompt("Workspace directory (agent RW access)")
                .default(default)
                .interact_text()
                .context("workspace prompt")?;
            let p = PathBuf::from(s);
            std::path::absolute(&p).with_context(|| format!("resolve path {}", p.display()))?
        } else {
            cwd
        }
    };

    Ok(CollectedInputs {
        name,
        posture,
        mappings,
        extra_hosts,
        output_dir,
        workspace,
    })
}

fn prompt_posture(theme: &ColorfulTheme) -> Result<Posture> {
    let variants = Posture::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|p| format!("{:<24}  {}", p.file_name(), p.description()))
        .collect();
    let selection = dialoguer::Select::with_theme(theme)
        .with_prompt("Posture")
        .items(&items)
        .default(1)
        .report(false)
        .interact()
        .context("posture prompt")?;
    let chosen = variants[selection].clone();
    eprintln!("  Posture  · {}", chosen.file_name());
    Ok(chosen)
}

fn prompt_mappings(theme: &ColorfulTheme) -> Result<Vec<Mapping>> {
    let variants = Mapping::value_variants();
    let items: Vec<String> = variants
        .iter()
        .map(|m| format!("{:<12}  {}", m.as_str(), m.description()))
        .collect();
    let defaults: Vec<bool> = variants
        .iter()
        .map(|m| matches!(m, Mapping::Anthropic))
        .collect();
    let selections = dialoguer::MultiSelect::with_theme(theme)
        .with_prompt("Mappings (space to toggle, enter to confirm)")
        .items(&items)
        .defaults(&defaults)
        .report(false)
        .interact()
        .context("mappings prompt")?;
    let chosen: Vec<Mapping> = selections
        .into_iter()
        .map(|i| variants[i].clone())
        .collect();
    eprintln!(
        "  Mappings · {}",
        chosen
            .iter()
            .map(Mapping::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(chosen)
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
    use strum::IntoEnumIterator;

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
            output_dir: PathBuf::from(TEST_WORKSPACE),
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
        for posture in Posture::iter() {
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
        for m in Mapping::iter() {
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
