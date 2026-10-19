//! Check 5: parse the unified `firma.toml`.
//!
//! The unified config is always sectioned. This check fails (fail-closed)
//! if either the `[authority]` or `[sidecar]` section is missing or does
//! not deserialize into its component config type.

#[cfg(test)]
use std::path::Path;

use firma_runtime_state::RuntimeLayout;

use crate::doctor::report::Check;

/// Validate the resolved `firma.toml`: both `[authority]` and `[sidecar]`
/// sections must be present and parse into their component config types.
#[must_use]
#[cfg(test)]
pub fn check(firma_toml: &Path, state: &RuntimeLayout) -> Check {
    let display = firma_toml.display().to_string();

    let parsed = match firma_config_loader::FirmaConfig::load(firma_toml) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Check::fail("config parsed", error.to_string()).with_detail("path", display);
        }
    };

    check_loaded(&parsed, state)
}

/// Validate an already-loaded `firma.toml`.
///
/// `state` is the same state directory the Sidecar will resolve its unset
/// artifact paths against. Validating without it reports a configuration the
/// Sidecar accepts — an `https://` Authority whose CA certificate is only in
/// the state directory, for instance — as a broken one.
#[must_use]
pub fn check_loaded(parsed: &firma_config_loader::FirmaConfig, state: &RuntimeLayout) -> Check {
    let display = parsed.origin().display().to_string();

    // [authority] is optional — agent-remote configs have no server section.
    //
    // `without_tls` because this check is about the file, not the host: whether
    // that Authority may serve plaintext is decided by the `--no-tls` flag of a
    // process this command knows nothing about, so resolving the TLS pair here
    // would report an absent certificate as a broken config.
    if let Ok(body) = parsed.raw_section("authority")
        && let Err(error) = firma_authority::AuthorityConfigBuilder::from_toml_str(&body, state)
            .map_err(|e| e.to_string())
            .and_then(|builder| builder.without_tls().build().map_err(|e| e.to_string()))
    {
        return Check::fail("config parsed", format!("[authority]: {display}: {error}"))
            .with_detail("path", display);
    }

    let sidecar_body = match parsed.raw_section("sidecar") {
        Ok(body) => body,
        Err(error) => {
            return Check::fail("config parsed", format!("[sidecar]: {error}"))
                .with_detail("path", display);
        }
    };
    match toml::from_str::<firma_config_schema::sidecar::SidecarConfig>(&sidecar_body) {
        Ok(schema) => {
            if let Err(error) = firma_sidecar::config::SidecarConfig::resolve(schema, state) {
                return Check::fail("config parsed", format!("[sidecar]: {display}: {error}"))
                    .with_detail("path", display);
            }
        }
        Err(error) => {
            return Check::fail("config parsed", format!("[sidecar]: {display}: {error}"))
                .with_detail("path", display);
        }
    }

    Check::ok("config parsed", display.clone()).with_detail("path", display)
}

#[cfg(test)]
mod tests {
    use firma_config_loader::CONFIG_FILE_NAME;

    use super::*;
    use crate::doctor::report::Status;

    fn write(dir: &Path, body: &str) -> std::path::PathBuf {
        let p = dir.join(CONFIG_FILE_NAME);
        std::fs::write(&p, body).unwrap();
        p
    }

    /// A state directory with no generated material, so these cases exercise
    /// the config file alone.
    fn empty_state(dir: &Path) -> RuntimeLayout {
        RuntimeLayout::from_root(dir.join("state"))
    }

    #[test]
    fn ok_when_no_authority_section_agent_remote() {
        // agent-remote configs have no [authority] — should not fail.
        let tmp = tempfile::tempdir().unwrap();
        let p = write(
            tmp.path(),
            "[sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"127.0.0.1:8080\"\n[sidecar.authority]\nurl = 'http://localhost:50051'\n",
        );
        let c = check(&p, &empty_state(tmp.path()));
        assert_eq!(c.status, Status::Ok, "got {c:?}");
    }

    #[test]
    fn fail_when_authority_section_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write(tmp.path(), "[authority]\nmax_ttl = \"not-a-duration\"\n");
        let c = check(&p, &empty_state(tmp.path()));
        assert_eq!(c.status, Status::Fail);
        assert!(c.reason.contains("[authority]"), "got {c:?}");
    }

    #[test]
    fn fail_when_authority_duration_cannot_be_represented_at_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write(
            tmp.path(),
            "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nmax_ttl = \"500ms\"\n",
        );
        let c = check(&p, &empty_state(tmp.path()));
        assert_eq!(c.status, Status::Fail);
        assert!(c.reason.contains("whole number of seconds"), "got {c:?}");
    }

    #[test]
    fn fail_when_sidecar_section_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write(
            tmp.path(),
            "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"127.0.0.1:0\"\n",
        );
        let c = check(&p, &empty_state(tmp.path()));
        assert_eq!(c.status, Status::Fail);
        assert!(c.reason.contains("[sidecar]"), "got {c:?}");
    }

    #[test]
    fn fail_when_toml_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write(tmp.path(), "@@not toml@@");
        let c = check(&p, &empty_state(tmp.path()));
        assert_eq!(c.status, Status::Fail);
    }

    #[test]
    fn ok_when_authority_and_sidecar_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write(
            tmp.path(),
            "[authority]\nmapping_rules_paths = ['mapping-rules.toml']\nlisten_addr = \"127.0.0.1:0\"\n\n[sidecar.interceptor]\nmode = \"http_proxy\"\nlisten_addr = \"127.0.0.1:8080\"\n[sidecar.authority]\nurl = 'http://localhost:50051'\n",
        );
        let c = check(&p, &empty_state(tmp.path()));
        assert_eq!(c.status, Status::Ok, "got {c:?}");
    }
}
