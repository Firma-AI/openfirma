//! Section extraction so one `firma.toml` serves every subcommand.

use std::path::Path;

/// A `firma.toml` parsed once. Use when more than one `[section]` is
/// needed from the same file (e.g. `doctor` reads both `[authority]`
/// and `[sidecar]`) so the file is read and parsed a single time.
#[derive(Debug, Clone)]
pub struct FirmaConfig {
    table: toml::Table,
    origin: String,
}

impl FirmaConfig {
    /// Read and parse `path` once.
    ///
    /// # Errors
    ///
    /// Returns the read or parse error as a string (caller wraps it).
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let table: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| format!("{}: {e}", path.display()))?;
        Ok(Self {
            table,
            origin: path.display().to_string(),
        })
    }

    /// The named section body re-serialized as standalone TOML.
    ///
    /// Supports dotted paths (e.g. `"authority.server"`) to address
    /// sub-tables. A missing section at any level is a hard error
    /// (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns a "missing section" or serialization error string.
    pub fn section(&self, section: &str) -> Result<String, String> {
        let parts: Vec<&str> = section.split('.').collect();
        let mut current = &self.table;
        for &part in &parts[..parts.len() - 1] {
            match current.get(part) {
                Some(toml::Value::Table(t)) => current = t,
                _ => {
                    return Err(format!(
                        "{}: missing required `[{section}]` section",
                        self.origin
                    ));
                }
            }
        }
        let last = parts.last().copied().unwrap_or(section);
        match current.get(last) {
            Some(toml::Value::Table(sub)) => {
                toml::to_string(sub).map_err(|e| format!("{}: {e}", self.origin))
            }
            _ => Err(format!(
                "{}: missing required `[{section}]` section",
                self.origin
            )),
        }
    }
}

/// Read `path` and return the named `[section]` body as standalone TOML.
///
/// The unified `firma.toml` is always sectioned. A missing `[section]`
/// is a hard error (fail-closed) — there is no flat-file fallback.
///
/// # Errors
///
/// Returns the read/parse error, or a "missing section" error, as a
/// string (caller wraps it).
pub fn load_section(path: &Path, section: &str) -> Result<String, String> {
    FirmaConfig::load(path)?.section(section)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn extracts_named_section() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(&p, "[sidecar]\nfoo = 1\n[authority]\nbar = 2\n").unwrap();
        let out = load_section(&p, "sidecar").unwrap();
        let t: toml::Table = out.parse().unwrap();
        assert_eq!(t.get("foo").and_then(toml::Value::as_integer), Some(1));
        assert!(t.get("bar").is_none());
    }

    #[test]
    fn nested_subtables_are_preserved() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(
            &p,
            "[sidecar.interceptor]\nmode = \"http_proxy\"\n[sidecar.policy]\nauthority_url = \"http://x\"\n",
        )
        .unwrap();
        let out = load_section(&p, "sidecar").unwrap();
        let t: toml::Table = out.parse().unwrap();
        assert!(
            t.get("interceptor")
                .and_then(toml::Value::as_table)
                .is_some()
        );
        assert!(t.get("policy").and_then(toml::Value::as_table).is_some());
    }

    #[test]
    fn missing_section_is_an_error() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(&p, "[authority]\nbar = 2\n").unwrap();
        let err = load_section(&p, "sidecar").unwrap_err();
        assert!(err.contains("sidecar"), "error names the section: {err}");
    }

    #[test]
    fn dotted_path_extracts_nested_section() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(
            &p,
            "[authority.server]\nlisten_addr = \"127.0.0.1:9443\"\n[authority.connect]\nurl = \"https://x\"\n",
        )
        .unwrap();
        let server = load_section(&p, "authority.server").unwrap();
        let t: toml::Table = server.parse().unwrap();
        assert_eq!(
            t.get("listen_addr").and_then(toml::Value::as_str),
            Some("127.0.0.1:9443")
        );
        let connect = load_section(&p, "authority.connect").unwrap();
        let t2: toml::Table = connect.parse().unwrap();
        assert_eq!(
            t2.get("url").and_then(toml::Value::as_str),
            Some("https://x")
        );
    }

    #[test]
    fn dotted_path_missing_is_an_error() {
        let tmp = tempdir().unwrap();
        let p = tmp.path().join("firma.toml");
        std::fs::write(&p, "[authority.connect]\nurl = \"https://x\"\n").unwrap();
        let err = load_section(&p, "authority.server").unwrap_err();
        assert!(err.contains("authority.server"), "error: {err}");
    }
}
