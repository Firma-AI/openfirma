//! Config discovery behavior through the public resolver API.

use std::assert_matches;
use std::path::{Path, PathBuf};

use firma_config_loader::{
    CONFIG_DIR_NAME, CONFIG_ENV_NAME, ConfigResolveError, ConfigResolver, ConfigSource,
    FirmaConfigCandidateAncestors,
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

fn touch_project_local(dir: &Path) -> PathBuf {
    let d = dir.join(CONFIG_DIR_NAME);
    fs::create_dir_all(&d).expect("create .firma dir");
    let f = d.join(firma_config_loader::CONFIG_FILE_NAME);
    fs::write(&f, "").expect("write config file");
    f
}

fn enter_nested_project(root: &Path) -> PathBuf {
    let ceiling = root.join("project");
    let nested = ceiling.join("sub").join("deep");
    fs::create_dir_all(&nested).expect("create nested project cwd");
    std::env::set_current_dir(&nested).expect("set cwd to nested project directory");
    ceiling
}

fn firma_config_env(root: &Path, file_name: &str) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vec![(
        std::ffi::OsString::from(CONFIG_ENV_NAME),
        root.join(file_name).into_os_string(),
    )]
}

#[test]
fn relative_flag_is_absolutized_and_wins_over_everything() {
    helper::run_isolated_with_env(
        |_| {
            vec![(
                std::ffi::OsString::from(CONFIG_ENV_NAME),
                std::ffi::OsString::from("env.toml"),
            )]
        },
        |root| {
            let flag = PathBuf::from("explicit.toml");
            fs::write(&flag, "").expect("write explicit config");
            fs::write("env.toml", "").expect("write environment config");
            touch_project_local(root);

            let resolved = unwrap_resolved(ConfigResolver::default().resolve_config(Some(&flag)));

            assert_eq!(resolved.source, ConfigSource::Flag);
            assert_eq!(resolved.config_file(), root.join(&flag));
            assert_eq!(resolved.config_dir(), root);
        },
    );
}

#[test]
fn explicit_missing_config_is_an_error() {
    helper::run_isolated(|root| {
        let missing = root.join("missing.toml");
        let error = ConfigResolver::default()
            .resolve_config(Some(&missing))
            .expect_err("resolution should fail");
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

        let error = ConfigResolver::default()
            .resolve_config(Some(&invalid))
            .expect_err("resolution should fail");
        assert_matches!(error, ConfigResolveError { config_source: ConfigSource::Flag, path, .. } if path == invalid);
    });
}

#[test]
fn relative_env_var_is_absolutized_and_beats_project_local() {
    helper::run_isolated_with_env(
        |_| {
            vec![(
                std::ffi::OsString::from(CONFIG_ENV_NAME),
                std::ffi::OsString::from("env.toml"),
            )]
        },
        |root| {
            let project = enter_nested_project(root);
            let env_file = std::env::current_dir()
                .expect("read nested project cwd")
                .join("env.toml");
            fs::write(&env_file, "").expect("write env config");
            touch_project_local(&project);

            let resolved = unwrap_resolved(ConfigResolver::default().resolve_config(None));

            assert_eq!(resolved.source, ConfigSource::EnvVar);
            assert_eq!(resolved.config_file(), env_file.as_path());
            assert_eq!(
                resolved.config_dir(),
                env_file.parent().expect("env config parent")
            );
        },
    );
}

#[test]
fn env_missing_config_is_an_error() {
    helper::run_isolated_with_env(
        |root| firma_config_env(root, "missing.toml"),
        |_| {
            let error = ConfigResolver::default()
                .resolve_config(None)
                .expect_err("resolution should fail");
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
        |root| firma_config_env(root, "invalid.toml"),
        |root| {
            let invalid = root.join("invalid.toml");
            fs::write(&invalid, "=").expect("write invalid config");

            let error = ConfigResolver::default()
                .resolve_config(None)
                .expect_err("resolution should fail");
            assert_matches!(error, ConfigResolveError { config_source: ConfigSource::EnvVar, path, .. } if path == invalid);
        },
    );
}

#[test]
fn project_local_found_in_cwd() {
    helper::run_isolated(|root| {
        let project_file = touch_project_local(root);
        let provider = ConfigResolver::default().walk_up_to(root);

        let resolved = unwrap_resolved(provider.resolve_config(None));

        assert_eq!(resolved.source, ConfigSource::ProjectLocal);
        assert_eq!(resolved.config_file(), project_file.as_path());
    });
}

#[test]
// Windows doesn't let a process delete the directory that's currently set as its current
// working directory.
#[cfg(unix)]
fn project_local_fails_if_we_cannot_determine_cwd() {
    helper::run_isolated(|root| {
        let provider = ConfigResolver::default().walk_up_to(root);
        // One way to get `current_dir` to fail is to delete the directory that's set as
        // current working directory of the process!
        fs::remove_dir_all(root).unwrap();
        let _resolved = provider.resolve_config(None).unwrap_err();
    });
}

#[test]
fn project_local_walks_up_to_ancestor() {
    helper::run_isolated(|root| {
        let project = enter_nested_project(root);
        let project_file = touch_project_local(&project);

        let resolved = unwrap_resolved(ConfigResolver::default().resolve_config(None));

        assert_eq!(resolved.source, ConfigSource::ProjectLocal);
        assert_eq!(resolved.config_file(), project_file.as_path());
    });
}

#[test]
fn project_local_closest_ancestor_wins() {
    helper::run_isolated(|root| {
        let project = enter_nested_project(root);
        touch_project_local(&project);
        let nested_file = touch_project_local(project.join("sub").as_path());

        let resolved = unwrap_resolved(ConfigResolver::default().resolve_config(None));

        assert_eq!(resolved.source, ConfigSource::ProjectLocal);
        assert_eq!(resolved.config_file(), nested_file.as_path());
    });
}

#[test]
fn project_local_invalid_toml_fails_closed_without_continuing_to_parent() {
    helper::run_isolated(|root| {
        let project = enter_nested_project(root);
        let nested = project.join("sub").join("deep");
        fs::create_dir_all(nested.join(CONFIG_DIR_NAME)).expect("create nested .firma dir");
        touch_project_local(&project);
        let invalid = nested
            .join(CONFIG_DIR_NAME)
            .join(firma_config_loader::CONFIG_FILE_NAME);
        fs::write(&invalid, "=").expect("write invalid config");

        let error = ConfigResolver::default()
            .resolve_config(None)
            .expect_err("resolution should fail");
        assert_matches!(error, ConfigResolveError { config_source: ConfigSource::ProjectLocal, path, .. } if path == invalid);
    });
}

#[cfg(unix)]
#[test]
fn project_local_unreadable_file_fails_closed_without_continuing_to_parent() {
    use std::os::unix::fs::PermissionsExt as _;

    fn set_mode(path: &Path, mode: u32) {
        let mut permissions = fs::metadata(path)
            .expect("read config metadata for permission update")
            .permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions).expect("update config permissions");
    }

    helper::run_isolated(|root| {
        let project = enter_nested_project(root);
        let nested = project.join("sub").join("deep");
        fs::create_dir_all(nested.join(CONFIG_DIR_NAME)).expect("create nested .firma dir");
        touch_project_local(&project);
        let unreadable = nested
            .join(CONFIG_DIR_NAME)
            .join(firma_config_loader::CONFIG_FILE_NAME);
        fs::write(&unreadable, "").expect("write unreadable config");
        set_mode(&unreadable, 0o000);
        if fs::read_to_string(&unreadable).is_ok() {
            set_mode(&unreadable, 0o600);
            return;
        }

        let error = ConfigResolver::default()
            .resolve_config(None)
            .expect_err("resolution should fail");
        assert_matches!(error, ConfigResolveError { config_source: ConfigSource::ProjectLocal, path, .. } if path == unreadable);

        set_mode(&unreadable, 0o600);
    });
}

#[test]
fn resolver_walks_up_to_project_local_with_ceiling() {
    helper::run_isolated(|root| {
        let ceiling = enter_nested_project(root);
        let project_file = touch_project_local(&ceiling);
        let provider = ConfigResolver::default().walk_up_to(&ceiling);

        let resolved = unwrap_resolved(provider.resolve_config(None));

        assert_eq!(resolved.source, ConfigSource::ProjectLocal);
        assert_eq!(resolved.config_file(), project_file.as_path());
    });
}

#[test]
fn resolver_stops_walk_at_ceiling() {
    helper::run_isolated(|root| {
        let ceiling = enter_nested_project(root);
        touch_project_local(root);
        let provider = ConfigResolver::default().walk_up_to(&ceiling);

        assert_matches!(provider.resolve_config(None).expect("resolve config"), None);
    });
}

#[test]
fn cwd_outside_ceiling_stops_before_searching() {
    helper::run_isolated(|root| {
        let ceiling = root.join("project");
        touch_project_local(root);
        let provider = ConfigResolver::default().walk_up_to(&ceiling);

        assert_matches!(provider.resolve_config(None).expect("resolve config"), None);
    });
}

#[test]
fn nothing_found_returns_none() {
    helper::run_isolated(|root| {
        let provider = ConfigResolver::default().walk_up_to(root);

        assert_matches!(provider.resolve_config(None).expect("resolve config"), None);
    });
}

fn candidate_dirs(start: &Path, ceiling: Option<&Path>) -> Vec<PathBuf> {
    FirmaConfigCandidateAncestors::new(start, ceiling)
        .map(|candidate| candidate.config_dir)
        .collect()
}

#[test]
fn candidates_walk_up_nearest_first() {
    let dirs = candidate_dirs(Path::new("/a/b/c"), None);
    assert_eq!(
        dirs,
        vec![
            PathBuf::from("/a/b/c/.firma"),
            PathBuf::from("/a/b/.firma"),
            PathBuf::from("/a/.firma"),
            PathBuf::from("/.firma"),
        ]
    );
}

#[test]
fn candidate_pairs_config_file_under_dir() {
    let first = FirmaConfigCandidateAncestors::new(Path::new("/a/b"), None)
        .next()
        .expect("at least one candidate");
    assert_eq!(first.config_dir, PathBuf::from("/a/b/.firma"));
    assert_eq!(first.config_file(), PathBuf::from("/a/b/.firma/firma.toml"));
}

#[test]
fn ceiling_is_inclusive_and_stops_walk() {
    let dirs = candidate_dirs(Path::new("/a/b/c"), Some(Path::new("/a/b")));
    assert_eq!(
        dirs,
        vec![PathBuf::from("/a/b/c/.firma"), PathBuf::from("/a/b/.firma"),],
        "walk yields the ceiling directory then stops"
    );
}

#[test]
fn ceiling_outside_start_yields_nothing() {
    let dirs = candidate_dirs(Path::new("/a/b"), Some(Path::new("/other")));
    assert!(dirs.is_empty());
}
