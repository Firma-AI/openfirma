//! Authority-owned policy and mapping defaults for locally generated launches.

use std::path::Path;

use crate::error::RunError;

const DEVELOPER_ISSUANCE: &str = "permit(principal, action, resource);\n";

/// Generated rules for one execution profile, used by a per-run Authority.
#[cfg(unix)]
pub fn mapping_rules(profile: firma_config_loader::AgentProfile) -> String {
    let mut text = String::new();
    if profile == firma_config_loader::AgentProfile::Vscode {
        append_vscode_rules(&mut text, true);
    } else {
        append_generic_rules(&mut text);
    }
    text
}

/// Generated rules persisted by the first-run prompt.
///
/// The persisted file outlives the run that wrote it and later serves every
/// execution profile, so it covers all of them. Hosts the VS Code profile keeps
/// out of interception also get HTTP rules, which other profiles need once
/// they intercept those hosts.
pub fn persisted_mapping_rules() -> String {
    let mut text = String::new();
    append_generic_rules(&mut text);
    append_vscode_rules(&mut text, false);
    text
}

fn append_vscode_rules(text: &mut String, skip_bypassed_http: bool) {
    for host in VSCODE_HOSTS {
        append_rule(text, Some("CONNECT"), host, None);
    }
    let bypassed = crate::sidecar::config::VSCODE_GITHUB_MITM_BYPASS_HOSTS;
    for host in VSCODE_HOSTS
        .iter()
        .filter(|host| !skip_bypassed_http || !bypassed.contains(host))
    {
        append_rule(text, None, host, Some("*"));
    }
}

fn append_generic_rules(text: &mut String) {
    for host in [
        "auth.openai.com",
        "api.openai.com",
        "chatgpt.com",
        "*.chatgpt.com",
        "api.anthropic.com",
        "platform.claude.com",
        "claude.ai",
        "console.anthropic.com",
        "*.anthropic.com",
    ] {
        append_rule(text, Some("CONNECT"), host, Some("/"));
    }
    for (method, host, path) in [
        (None, "auth.openai.com", "/api/accounts/deviceauth/*"),
        (Some("POST"), "auth.openai.com", "/oauth/token"),
        (None, "auth.openai.com", "/oauth/*"),
        (None, "api.openai.com", "/v1/*"),
        (None, "chatgpt.com", "/backend-api/*"),
        (None, "*.chatgpt.com", "/backend-api/*"),
        (None, "api.anthropic.com", "/api/*"),
        (None, "platform.claude.com", "/v1/*"),
        (None, "*.anthropic.com", "/*"),
        (None, "claude.ai", "*"),
        (None, "console.anthropic.com", "*"),
    ] {
        append_rule(text, method, host, Some(path));
    }
}

fn append_rule(text: &mut String, method: Option<&str>, host: &str, path: Option<&str>) {
    use std::fmt::Write as _;
    text.push_str("[[rules]]\n");
    if let Some(method) = method {
        let _ = writeln!(text, "method = {}", toml::Value::String(method.into()));
    }
    let _ = writeln!(text, "host = {}", toml::Value::String(host.into()));
    if let Some(path) = path {
        let _ = writeln!(text, "path = {}", toml::Value::String(path.into()));
    }
    text.push_str("action_class = \"communication.external.send\"\n\n");
}

const VSCODE_HOSTS: &[&str] = &[
    "update.code.visualstudio.com",
    "code.visualstudio.com",
    "*.code.visualstudio.com",
    "vscode.dev",
    "*.vscode.dev",
    "az764295.vo.msecnd.net",
    "vscodeexperiments.azureedge.net",
    "default.exp-tas.com",
    "marketplace.visualstudio.com",
    "*.gallerycdn.vsassets.io",
    "*.gallery.vsassets.io",
    "*.vscode-unpkg.net",
    "*.vscode-cdn.net",
    "vscode-sync.trafficmanager.net",
    "*.vscode-sync.trafficmanager.net",
    "login.microsoftonline.com",
    "login.live.com",
    "*.microsoft.com",
    "*.msauth.net",
    "*.msftauth.net",
    "github.com",
    "*.github.com",
    "api.github.com",
    "uploads.github.com",
    "*.githubusercontent.com",
    "*.ghe.com",
    "accounts.google.com",
    "*.gstatic.com",
    "*.googleusercontent.com",
    "appleid.apple.com",
    "idmsa.apple.com",
    "*.cdn-apple.com",
];

/// Issuance policy for a generated launch. Only the `developer` profile is
/// registered, and it issues any requested capability: enforcement stays with
/// the streamed policy bundle.
pub fn issuance_policy(profile: &str) -> Result<&'static str, RunError> {
    if profile == firma_authority::DEFAULT_PROFILE {
        Ok(DEVELOPER_ISSUANCE)
    } else {
        Err(RunError::AuthorityUnknownProfile {
            name: profile.to_string(),
        })
    }
}

pub fn materialize_policy(dir: &Path, profile: &str, content: &str) -> Result<(), RunError> {
    firma_fs::create_private_dir_all(dir).map_err(|error| RunError::Internal(error.to_string()))?;
    let entries = std::fs::read_dir(dir)
        .map_err(|error| RunError::Internal(format!("read policies {}: {error}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|error| RunError::Internal(error.to_string()))?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "cedar")
        {
            return Ok(());
        }
    }
    let path = dir.join(format!("{profile}.cedar"));
    firma_fs::write_private_file(&path, content.as_bytes())
        .map_err(|error| RunError::Internal(format!("write policy {}: {error}", path.display())))
}
