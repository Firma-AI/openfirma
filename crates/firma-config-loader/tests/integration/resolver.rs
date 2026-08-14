//! Config discovery behavior through the public resolver API.
//!
//! Discovery resolves `firma.toml` from a fixed precedence — `--config`,
//! `$FIRMA_CONFIG`, then the user-controlled trusted config directory — with no
//! cwd/ancestor walk. These tests pin that precedence and, crucially, prove a
//! planted `./.firma/firma.toml` is never selected.

use std::assert_matches;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use firma_config_loader::{
    CONFIG_DIR_NAME, CONFIG_ENV_NAME, CONFIG_FILE_NAME, ConfigResolveError, ConfigSource,
    resolve_config,
};
use fs_err as fs;

use crate::helper;

fn unwrap_resolved(
    result: Result<Option<firma_config_loader::ResolvedConfig>, ConfigResolveError>,
) -> firma_config_loader::ResolvedConfig {
    result
        .expect("resolve config")
        .expect("config should be found")
}

fn env(key: &str, value: &OsStr) -> (OsString, OsString) {
    (OsString::from(key), value.to_os_string())
}

/// Point OS home discovery at `home` so the trusted config directory resolves
/// to `<home>/.firma`, deterministically, regardless of the real environment.
#[cfg(unix)]
fn home_env(home: &Path) -> Vec<(OsString, OsString)> {
    vec![env("HOME", home.as_os_str())]
}

#[cfg(windows)]
fn home_env(home: &Path) -> Vec<(OsString, OsString)> {
    vec![env("USERPROFILE", home.as_os_str())]
}

/// The trusted `.firma/` directory for a HOME-rooted home directory.
fn trusted_dir(home: &Path) -> PathBuf {
    home.join(CONFIG_DIR_NAME)
}

/// Write `contents` to `<dir>/firma.toml`, creating `dir`, and return the path.
fn write_config(dir: &Path, contents: &str) -> PathBuf {
    fs::create_dir_all(dir).expect("create config dir");
    let file = dir.join(CONFIG_FILE_NAME);
    fs::write(&file, contents).expect("write config file");
    file
}

/// Plant a `.firma/firma.toml` under `dir`, emulating an attacker writing into
/// the workspace or an ancestor. Selecting this file is a security failure.
fn plant_project_local(dir: &Path) -> PathBuf {
    write_config(&dir.join(CONFIG_DIR_NAME), "")
}

#[test]
fn flag_wins_over_everything() {
    helper::run_isolated(|root| {
        let flag = root.join("explicit.toml");
        fs::write(&flag, "").expect("write explicit config");

        let resolved = unwrap_resolved(resolve_config(Some(&flag)));

        assert_eq!(resolved.source, ConfigSource::Flag);
        assert_eq!(resolved.config_file(), flag.as_path());
        assert_eq!(resolved.config_dir(), root);
    });
}

#[test]
fn explicit_missing_config_is_an_error() {
    helper::run_isolated(|root| {
        let missing = root.join("missing.toml");
        let error = resolve_config(Some(&missing)).expect_err("resolution should fail");
        assert_matches!(
            error,
            ConfigResolveError {
                config_source: ConfigSource::Flag,
                ..
            }
        );
    });
}

#[test]
fn explicit_invalid_toml_is_an_error() {
    helper::run_isolated(|root| {
        let invalid = root.join("invalid.toml");
        fs::write(&invalid, "=").expect("write invalid config");

        let error = resolve_config(Some(&invalid)).expect_err("resolution should fail");
        assert_matches!(error, ConfigResolveError { config_source: ConfigSource::Flag, path, .. } if path == invalid);
    });
}

#[test]
fn env_var_beats_trusted_dir() {
    helper::run_isolated_with_env(
        |root| {
            let mut vars = home_env(root);
            vars.push(env(CONFIG_ENV_NAME, root.join("env.toml").as_os_str()));
            vars
        },
        |root| {
            let env_file = root.join("env.toml");
            fs::write(&env_file, "").expect("write env config");
            // A trusted-dir config also exists; the env var must still win.
            write_config(&trusted_dir(root), "");

            let resolved = unwrap_resolved(resolve_config(None));

            assert_eq!(resolved.source, ConfigSource::EnvVar);
            assert_eq!(resolved.config_file(), env_file.as_path());
        },
    );
}

#[test]
fn env_missing_config_is_an_error() {
    helper::run_isolated_with_env(
        |root| vec![env(CONFIG_ENV_NAME, root.join("missing.toml").as_os_str())],
        |_| {
            let error = resolve_config(None).expect_err("resolution should fail");
            assert_matches!(
                error,
                ConfigResolveError {
                    config_source: ConfigSource::EnvVar,
                    ..
                }
            );
        },
    );
}

#[test]
fn env_invalid_toml_is_an_error() {
    helper::run_isolated_with_env(
        |root| vec![env(CONFIG_ENV_NAME, root.join("invalid.toml").as_os_str())],
        |root| {
            let invalid = root.join("invalid.toml");
            fs::write(&invalid, "=").expect("write invalid config");

            let error = resolve_config(None).expect_err("resolution should fail");
            assert_matches!(error, ConfigResolveError { config_source: ConfigSource::EnvVar, path, .. } if path == invalid);
        },
    );
}

#[test]
fn trusted_dir_config_is_found() {
    helper::run_isolated_with_env(home_env, |root| {
        let config = write_config(&trusted_dir(root), "");

        let resolved = unwrap_resolved(resolve_config(None));

        assert_eq!(resolved.source, ConfigSource::Home);
        assert_eq!(resolved.config_file(), config.as_path());
        assert_eq!(resolved.config_dir(), trusted_dir(root));
    });
}

#[test]
fn nothing_found_returns_none() {
    helper::run_isolated_with_env(home_env, |_| {
        assert_matches!(resolve_config(None).expect("resolve config"), None);
    });
}

#[test]
fn trusted_dir_invalid_toml_is_an_error() {
    helper::run_isolated_with_env(home_env, |root| {
        let invalid = write_config(&trusted_dir(root), "=");

        let error = resolve_config(None).expect_err("resolution should fail");
        assert_matches!(error, ConfigResolveError { config_source: ConfigSource::Home, path, .. } if path == invalid);
    });
}

/// Security regression: a planted `./.firma/firma.toml` in the cwd or any
/// ancestor must never be selected. Discovery no longer walks the tree.
#[test]
fn planted_project_local_config_is_ignored() {
    helper::run_isolated_with_env(
        // `home` is a sibling of the working tree, with no trusted config.
        |root| home_env(&root.join("home")),
        |root| {
            let workspace = root.join("workspace").join("nested");
            fs::create_dir_all(&workspace).expect("create nested workspace");
            std::env::set_current_dir(&workspace).expect("enter nested workspace");
            // Attacker plants configs in cwd and an ancestor.
            plant_project_local(&workspace);
            plant_project_local(&root.join("workspace"));

            assert_matches!(resolve_config(None).expect("resolve config"), None);
        },
    );
}

/// Fail closed: with no home-anchoring variable we refuse to guess a location
/// rather than fall back to an agent-writable path.
#[test]
fn home_unset_fails_closed() {
    helper::run_isolated_with_env(
        |_| {
            #[cfg(unix)]
            {
                vec![env("HOME", OsStr::new(""))]
            }
            #[cfg(windows)]
            {
                vec![env("USERPROFILE", OsStr::new(""))]
            }
        },
        |_| {
            let error = resolve_config(None).expect_err("resolution should fail closed");
            assert_matches!(
                error,
                ConfigResolveError {
                    config_source: ConfigSource::Home,
                    ..
                }
            );
        },
    );
}

/// `$XDG_CONFIG_HOME` is deliberately ignored: the trusted dir is always
/// `~/.firma`. A config placed under XDG is not discovered.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn xdg_config_home_is_ignored() {
    helper::run_isolated_with_env(
        |root| {
            vec![
                env("HOME", root.join("home").as_os_str()),
                env("XDG_CONFIG_HOME", root.join("xdg").as_os_str()),
            ]
        },
        |root| {
            // Config only under XDG; HOME has none. Must resolve to nothing.
            write_config(&root.join("xdg").join("firma"), "");

            assert_matches!(resolve_config(None).expect("resolve config"), None);
        },
    );
}

/// Security guard: a relative (non-empty) `HOME` is rejected. The trusted dir
/// must never resolve against the cwd, so discovery fails closed instead of
/// reading a cwd-relative `./.firma`.
#[cfg(unix)]
#[test]
fn relative_home_fails_closed() {
    helper::run_isolated_with_env(
        |_| vec![env("HOME", OsStr::new("relative/home"))],
        |_| {
            let error = resolve_config(None).expect_err("relative HOME must fail closed");
            assert_matches!(
                error,
                ConfigResolveError {
                    config_source: ConfigSource::Home,
                    ..
                }
            );
        },
    );
}

/// A trusted-dir `firma.toml` that exists but cannot be read fails closed: a
/// non-`NotFound` IO error must not be swallowed as "no config".
#[cfg(unix)]
#[test]
fn trusted_dir_unreadable_file_fails_closed() {
    use std::os::unix::fs::PermissionsExt as _;

    fn set_mode(path: &Path, mode: u32) {
        let mut perms = fs::metadata(path)
            .expect("read config metadata")
            .permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).expect("update config permissions");
    }

    helper::run_isolated_with_env(home_env, |root| {
        let unreadable = write_config(&trusted_dir(root), "");
        set_mode(&unreadable, 0o000);
        // Root (or a filesystem that ignores mode bits) can still read it; skip.
        if fs::read_to_string(&unreadable).is_ok() {
            set_mode(&unreadable, 0o600);
            return;
        }

        let error = resolve_config(None).expect_err("unreadable config must fail closed");
        assert_matches!(error, ConfigResolveError { config_source: ConfigSource::Home, path, .. } if path == unreadable);

        set_mode(&unreadable, 0o600);
    });
}
