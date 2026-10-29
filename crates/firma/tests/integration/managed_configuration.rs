use std::path::Path;
use std::process::Command;

#[test]
fn extra_hosts_reach_preserved_authority_mapping_lists_without_duplicates() -> anyhow::Result<()> {
    for paths in [
        vec![],
        vec!["custom-base.toml"],
        vec!["custom-base.toml", "./mapping-rules.toml"],
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("firma.toml");
        let paths = toml::Value::Array(
            paths
                .into_iter()
                .map(|path| toml::Value::String(path.into()))
                .collect(),
        );
        std::fs::write(
            &path,
            format!(
                "[authority]\nmapping_rules_paths = {paths}\n\
                 [sidecar.authority]\nagent_id = 'agt_01j0000000e008000000000001'\n\
                 url = 'https://[::1]:50051'\n"
            ),
        )?;
        let authored =
            "[[rules]]\nhost = 'original.example'\npath = '*'\naction_class = 'code.read'\n";
        std::fs::write(root.join("custom-base.toml"), authored)?;
        std::fs::write(root.join("mapping-rules.toml"), "# generated mappings\n")?;
        for _ in 0..2 {
            let output = Command::new(env!("CARGO_BIN_EXE_firma"))
                .args([
                    "config",
                    "--yes",
                    "--extra-hosts",
                    "new.example",
                    "--output-dir",
                ])
                .arg(root)
                .arg("--state-dir")
                .arg(root.join("state"))
                .output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
            let active_paths = config["authority"]["mapping_rules_paths"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("producer paths missing"))?;
            let original_paths = paths
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("fixture paths"))?;
            assert!(
                active_paths.starts_with(original_paths),
                "authored paths changed"
            );
            let mut active_rules = Vec::new();
            for path in active_paths {
                let path = path
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("non-string producer path"))?;
                let file: toml::Value = toml::from_str(&std::fs::read_to_string(root.join(path))?)?;
                if let Some(rules) = file.get("rules").and_then(toml::Value::as_array) {
                    active_rules.extend(rules.iter().cloned());
                }
            }
            let mut extra_rules: Vec<_> = active_rules
                .into_iter()
                .filter(|rule| {
                    matches!(
                        rule["host"].as_str(),
                        Some("new.example" | "new.example:443")
                    )
                })
                .collect();
            extra_rules.sort_by_key(|rule| rule["host"].as_str().map(str::to_owned));
            let expected: toml::Value = toml::from_str(
                "[[rules]]\nhost = 'new.example'\npath = '*'\n\
                 action_class = 'communication.external.send'\n\
                 [[rules]]\nhost = 'new.example:443'\nmethod = 'CONNECT'\n\
                 action_class = 'communication.external.send'\n",
            )?;
            assert_eq!(
                toml::Value::Array(extra_rules),
                expected["rules"],
                "extra hosts missing or duplicated in {active_paths:?}"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("custom-base.toml"))?,
                authored
            );
        }
    }
    Ok(())
}

fn remote_config(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_firma"));
    command.args([
        "config",
        "--yes",
        "--mode",
        "agent-remote",
        "--agent-id",
        "agt_01j0000000e008000000000001",
        "--authority-url",
        "https://authority.example.com:9443",
        "--profile",
        "codex",
    ]);
    command.arg("--output-dir").arg(root.join("config"));
    command.arg("--state-dir").arg(root.join("state"));
    command
        .arg("--authority-ca-cert")
        .arg(root.join("remote-ca.crt"));
    command
        .arg("--authority-pub-key")
        .arg(root.join("remote-authority.pub"));
    command
}

#[test]
fn remote_generation_and_conversion_leave_local_mapping_files_untouched() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let initial = remote_config(root).output()?;
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let path = root.join("config/firma.toml");
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    assert!(config["sidecar"].get("mapping").is_none());
    assert!(config.get("authority").is_none());
    assert!(!root.join("config/mapping-rules.toml").exists());
    assert_eq!(std::fs::read_dir(root.join("config/mappings"))?.count(), 0);

    let local_file = root.join("config/operator.toml");
    let contents = "# operator-owned mapping file\n";
    std::fs::write(&local_file, contents)?;
    let converted = remote_config(root).arg("--force").output()?;
    assert!(
        converted.status.success(),
        "{}",
        String::from_utf8_lossy(&converted.stderr)
    );
    assert_eq!(std::fs::read_to_string(local_file)?, contents);
    Ok(())
}

#[test]
fn credentialed_remote_to_local_conversion_drops_remote_authentication() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let initial = remote_config(root).output()?;
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let path = root.join("config/firma.toml");
    let credentials = "\n[sidecar.authority.credentials]\nworkspace_id = 'ws-example'\nsidecar_id = 'sc-example'\npre_shared_key_env = 'REMOTE_AUTHORITY_PSK'\n";
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let authority = config["sidecar"]["authority"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("authority table missing"))?;
    for (key, value) in [
        ("connect_addr", "192.0.2.42:9443"),
        ("tls_client_cert_path", "remote-client.crt"),
        ("tls_client_key_path", "remote-client.key"),
    ] {
        authority.insert(key.into(), toml::Value::String(value.into()));
    }
    std::fs::write(&path, format!("{}{credentials}", toml::to_string(&config)?))?;

    let remote = remote_config(root).output()?;
    assert!(
        remote.status.success(),
        "{}",
        String::from_utf8_lossy(&remote.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    assert_eq!(
        config["sidecar"]["authority"]["credentials"]["pre_shared_key_env"].as_str(),
        Some("REMOTE_AUTHORITY_PSK")
    );
    assert_eq!(
        config["sidecar"]["authority"]["connect_addr"].as_str(),
        Some("192.0.2.42:9443")
    );
    assert_eq!(
        config["sidecar"]["authority"]["tls_client_cert_path"].as_str(),
        Some("remote-client.crt")
    );
    assert_eq!(
        config["sidecar"]["authority"]["tls_client_key_path"].as_str(),
        Some("remote-client.key")
    );

    let local = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
        .arg(root.join("config"))
        .arg("--state-dir")
        .arg(root.join("state"))
        .output()?;
    assert!(
        local.status.success(),
        "{}",
        String::from_utf8_lossy(&local.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    assert_eq!(
        config["authority"]["mapping_rules_paths"][0].as_str(),
        Some("mapping-rules.toml")
    );
    assert!(root.join("config/mapping-rules.toml").is_file());
    let authority = &config["sidecar"]["authority"];
    for key in [
        "connect_addr",
        "tls_client_cert_path",
        "tls_client_key_path",
    ] {
        assert!(
            authority.get(key).is_none(),
            "stale remote {key}: {authority}"
        );
    }

    let doctor = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["doctor", "--json", "--config"])
        .arg(&path)
        .arg("--state-dir")
        .arg(root.join("state"))
        .args(["--timeout-ms", "250"])
        .current_dir(root)
        .output()?;
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(
        doctor.status.code().map(i64::from),
        report["exit_code"].as_i64()
    );
    let checks = report["checks"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("doctor checks missing"))?;
    let config_check = checks
        .iter()
        .find(|check| check["category"] == "config parsed")
        .ok_or_else(|| anyhow::anyhow!("doctor config check missing"))?;
    assert_eq!(config_check["status"], "ok", "{config_check}");
    assert!(config["sidecar"]["authority"].get("credentials").is_none());
    Ok(())
}

#[test]
fn local_rerun_compares_authority_endpoints_without_discarding_equivalent_routing()
-> anyhow::Result<()> {
    for (listen, old_url, preserve) in [
        ("[::1]:50051", "https://[0:0:0:0:0:0:0:1]:50051", true),
        ("127.0.0.1:443", "https://127.0.0.1", true),
        ("127.0.0.1:50051", "http://127.0.0.1:50051", true),
        ("127.0.0.1:443", "http://127.0.0.1", false),
        ("[::1]:50051", "https://[::1]:50052", false),
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let config_dir = root.join("config");
        std::fs::create_dir(&config_dir)?;
        let path = config_dir.join("firma.toml");
        let original = format!(
            "[authority]\nlisten_addr = '{listen}'\nmapping_rules_paths = ['custom-base.toml']\n\
             [sidecar.authority]\nagent_id = 'agt_01j0000000e008000000000001'\n\
             url = '{old_url}'\nconnect_addr = '127.0.0.1:55051'\n\
             tls_client_cert_path = 'local-client.crt'\ntls_client_key_path = 'local-client.key'\n"
        );
        std::fs::write(&path, &original)?;
        let output = Command::new(env!("CARGO_BIN_EXE_firma"))
            .args(["config", "--yes", "--output-dir"])
            .arg(&config_dir)
            .arg("--state-dir")
            .arg(root.join("state"))
            .output()?;
        assert!(
            output.status.success(),
            "{old_url}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
        let original: toml::Value = toml::from_str(&original)?;
        let authority = &config["sidecar"]["authority"];
        assert_eq!(
            authority["url"].as_str(),
            Some(format!("https://{listen}").as_str())
        );
        assert_eq!(
            config["authority"]["mapping_rules_paths"],
            toml::Value::Array(vec![toml::Value::String("custom-base.toml".into())])
        );
        for key in [
            "connect_addr",
            "tls_client_cert_path",
            "tls_client_key_path",
        ] {
            assert_eq!(
                authority.get(key),
                preserve.then(|| &original["sidecar"]["authority"][key]),
                "{old_url} -> https://{listen}: {key}"
            );
        }
    }
    Ok(())
}

#[test]
fn local_rerun_preserves_authority_owned_mapping_inputs() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let config_dir = root.join("config");
    std::fs::create_dir(&config_dir)?;
    let path = config_dir.join("firma.toml");
    let original = "\
[authority]
listen_addr = '127.0.0.1:50051'
mapping_rules_paths = ['custom-base.toml', 'mappings/github.toml', 'mappings/gmail.toml']
[sidecar.authority]
agent_id = 'agt_01j0000000e008000000000001'
url = 'http://127.0.0.1:50051'
connect_addr = '127.0.0.1:50051'
tls_client_cert_path = 'local-client.crt'
tls_client_key_path = 'local-client.key'
[run]
profile = 'generic'
";
    std::fs::write(&path, original)?;
    std::fs::write(config_dir.join("custom-base.toml"), "# operator mappings\n")?;
    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["config", "--yes", "--output-dir"])
        .arg(&config_dir)
        .arg("--state-dir")
        .arg(root.join("state"))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let original: toml::Value = toml::from_str(original)?;
    assert_eq!(
        config["authority"]["mapping_rules_paths"],
        original["authority"]["mapping_rules_paths"]
    );
    for key in [
        "connect_addr",
        "tls_client_cert_path",
        "tls_client_key_path",
    ] {
        assert_eq!(
            config["sidecar"]["authority"][key],
            original["sidecar"]["authority"][key]
        );
    }
    assert!(config_dir.join("mappings/github.toml").is_file());
    assert!(config_dir.join("mappings/gmail.toml").is_file());
    assert_eq!(
        std::fs::read_to_string(config_dir.join("custom-base.toml"))?,
        "# operator mappings\n"
    );
    let selected = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["config", "--yes", "--mapping", "openai", "--output-dir"])
        .arg(&config_dir)
        .arg("--state-dir")
        .arg(root.join("state"))
        .output()?;
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    assert_eq!(
        config["authority"]["mapping_rules_paths"],
        toml::Value::Array(vec![
            toml::Value::String("custom-base.toml".into()),
            toml::Value::String("mappings/openai.toml".into()),
        ])
    );
    assert!(config_dir.join("mappings/openai.toml").is_file());
    Ok(())
}

#[test]
fn rerun_infers_local_authority_with_default_listener() -> anyhow::Result<()> {
    for has_sidecar in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let config_dir = root.join("config");
        std::fs::create_dir(&config_dir)?;
        let path = config_dir.join("firma.toml");
        let mut original = "[authority]\nmapping_rules_paths = ['custom-base.toml']\n".to_string();
        if has_sidecar {
            original.push_str(
                "[sidecar.authority]\n\
                 agent_id = 'agt_01j0000000e008000000000001'\n\
                 url = 'https://[::1]:50051'\n\
                 ca_cert_paths = ['local-ca.crt']\n\
                 public_key_path = 'local.pub'\n",
            );
        }
        std::fs::write(&path, &original)?;
        let output = Command::new(env!("CARGO_BIN_EXE_firma"))
            .args(["config", "--yes", "--output-dir"])
            .arg(&config_dir)
            .arg("--state-dir")
            .arg(root.join("state"))
            .current_dir(root)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
        let authority = config
            .get("authority")
            .ok_or_else(|| anyhow::anyhow!("local Authority removed: {config}"))?;
        assert_eq!(authority["listen_addr"].as_str(), Some("[::1]:50051"));
        assert_eq!(
            authority["mapping_rules_paths"],
            toml::Value::Array(vec![toml::Value::String("custom-base.toml".into())])
        );
        assert_eq!(config.get("sidecar").is_some(), has_sidecar);
        if has_sidecar {
            assert_eq!(
                config["sidecar"]["authority"]["url"].as_str(),
                Some("https://[::1]:50051")
            );
            assert!(
                config["sidecar"]["authority"]
                    .get("ca_cert_paths")
                    .is_none()
            );
            assert!(
                config["sidecar"]["authority"]
                    .get("public_key_path")
                    .is_none()
            );
        }
    }
    Ok(())
}

#[test]
fn authority_mode_replaces_generated_selections_and_keeps_authored_inputs() -> anyhow::Result<()> {
    // A standalone Authority publishes the selection, so `--mapping` replaces
    // the generated vendor selection while authored inputs survive.
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let config_dir = root.join("config");
    std::fs::create_dir(&config_dir)?;
    let path = config_dir.join("firma.toml");
    let original = "\
[authority]
listen_addr = '127.0.0.1:50051'
mapping_rules_paths = ['custom-base.toml', 'mappings/github.toml']
policy_dir = 'policies/'
issuance_policy_dir = 'issuance-policies/'
max_ttl = '1h'
bundle_ttl = '30s'
[run]
profile = 'generic'
";
    std::fs::write(&path, original)?;
    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args([
            "config",
            "--yes",
            "--mode",
            "authority",
            "--mapping",
            "gmail",
            "--output-dir",
        ])
        .arg(&config_dir)
        .arg("--state-dir")
        .arg(root.join("state"))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    assert_eq!(
        config["authority"]["mapping_rules_paths"],
        toml::Value::Array(vec![
            toml::Value::String("custom-base.toml".into()),
            toml::Value::String("mappings/gmail.toml".into()),
        ])
    );
    assert!(config_dir.join("mappings/gmail.toml").is_file());
    Ok(())
}

#[test]
fn remote_generation_rejects_local_mapping_flags_before_writing() -> anyhow::Result<()> {
    for flags in [
        ["--mapping", "github"],
        ["--extra-hosts", "api.example.com"],
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let output = remote_config(root).args(flags).output()?;
        assert!(!output.status.success());
        insta::allow_duplicates! {
            insta::assert_snapshot!(String::from_utf8_lossy(&output.stderr), @"[ERR]  --mapping and --extra-hosts are local Authority options; manage remote Authority mappings centrally");
        }
        assert!(!root.join("config").exists());
        assert!(!root.join("state").exists());
    }
    Ok(())
}

#[test]
fn kept_remote_to_local_conversion_drops_stale_remote_routing() -> anyhow::Result<()> {
    // A remote-pointing Sidecar with a kept `[authority]` section infers as
    // AgentLocal, so mode comparison alone misses it. Converting to
    // `agent-local` must still drop the stale remote route and client
    // identity while keeping the local producer list.
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    let config_dir = root.join("config");
    std::fs::create_dir(&config_dir)?;
    let path = config_dir.join("firma.toml");
    let original = "\
[authority]
listen_addr = '127.0.0.1:50051'
mapping_rules_paths = ['custom-base.toml']
policy_dir = 'policies/'
issuance_policy_dir = 'issuance-policies/'
max_ttl = '1h'
bundle_ttl = '30s'
[sidecar.authority]
agent_id = 'agt_01j0000000e008000000000001'
url = 'https://authority.example.com:9443'
connect_addr = '192.0.2.42:9443'
tls_client_cert_path = 'remote-client.crt'
tls_client_key_path = 'remote-client.key'
ca_cert_paths = ['remote-ca.crt']
public_key_path = 'remote.pub'
[sidecar.authority.credentials]
workspace_id = 'ws-example'
sidecar_id = 'sc-example'
pre_shared_key_env = 'REMOTE_PSK'
[run]
profile = 'generic'
";
    std::fs::write(&path, original)?;
    let output = Command::new(env!("CARGO_BIN_EXE_firma"))
        .args(["config", "--yes", "--mode", "agent-local", "--output-dir"])
        .arg(&config_dir)
        .arg("--state-dir")
        .arg(root.join("state"))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    assert_eq!(
        config["authority"]["mapping_rules_paths"],
        toml::Value::Array(vec![toml::Value::String("custom-base.toml".into())])
    );
    let authority = &config["sidecar"]["authority"];
    assert_eq!(authority["url"].as_str(), Some("https://127.0.0.1:50051"));
    for key in [
        "connect_addr",
        "tls_client_cert_path",
        "tls_client_key_path",
        "ca_cert_paths",
        "public_key_path",
        "credentials",
    ] {
        assert!(
            authority.get(key).is_none(),
            "stale remote {key}: {authority}"
        );
    }
    Ok(())
}
