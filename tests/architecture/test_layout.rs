//! Keep crate integration tests collapsed into a single binary wherever
//! practical. Every top-level Rust entrypoint under `tests/` becomes its own
//! integration-test binary, and each binary pays its own link step. That slows
//! iteration speed across the workspace as the test count grows.
//!
//! For background and rationale, see:
//! <https://matklad.github.io/2021/02/27/delete-cargo-integration-tests.html>

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use guppy::MetadataCommand;

#[test]
fn crate_tests_use_single_binary_layout() -> Result<(), Box<dyn std::error::Error>> {
    let graph = MetadataCommand::new().build_graph()?;
    let workspace_root = graph.workspace().root();
    let mut violations = Vec::new();

    for package in graph.workspace().iter() {
        let Some(package_root) = package.manifest_path().parent() else {
            continue;
        };
        let tests_dir = package_root.join("tests");
        if !tests_dir.is_dir() {
            continue;
        }

        if let Some(violation) =
            validate_tests_dir(workspace_root.as_std_path(), tests_dir.as_std_path())?
        {
            violations.push(violation);
        }
    }

    assert!(
        violations.is_empty(),
        "crate test layout violations:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn validate_tests_dir(workspace_root: &Path, tests_dir: &Path) -> io::Result<Option<String>> {
    let mut top_level_rust_files = Vec::new();
    let mut rust_bearing_dirs = Vec::new();

    for entry in fs::read_dir(tests_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_file() && path.extension() == Some(OsStr::new("rs")) {
            top_level_rust_files.push(path);
            continue;
        }

        if file_type.is_dir() && contains_rust_sources(&path)? {
            rust_bearing_dirs.push(path);
        }
    }

    top_level_rust_files.sort();
    rust_bearing_dirs.sort();

    if top_level_rust_files.is_empty() && rust_bearing_dirs.is_empty() {
        return Ok(None);
    }

    if top_level_rust_files.len() == 1 && rust_bearing_dirs.is_empty() {
        return Ok(None);
    }

    if top_level_rust_files.is_empty()
        && rust_bearing_dirs.len() == 1
        && rust_bearing_dirs[0].file_name() == Some(OsStr::new("integration"))
    {
        let main_rs = rust_bearing_dirs[0].join("main.rs");
        if main_rs.is_file() {
            return Ok(None);
        }

        return Ok(Some(format!(
            "- {}: `tests/integration/` contains Rust sources but is missing `tests/integration/main.rs`",
            display_path(workspace_root, tests_dir)
        )));
    }

    Ok(Some(format!(
        "- {}: expected exactly one `tests/<name>.rs` file or `tests/integration/main.rs`; found top-level Rust files [{}] and Rust-bearing directories [{}]",
        display_path(workspace_root, tests_dir),
        display_paths(workspace_root, &top_level_rust_files),
        display_paths(workspace_root, &rust_bearing_dirs)
    )))
}

fn contains_rust_sources(dir: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_file() && path.extension() == Some(OsStr::new("rs")) {
            return Ok(true);
        }

        if file_type.is_dir() && contains_rust_sources(&path)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn display_paths(workspace_root: &Path, paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "none".to_string();
    }

    paths
        .iter()
        .map(|path| display_path(workspace_root, path))
        .collect::<Vec<_>>()
        .join(", ")
}

fn display_path(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .display()
        .to_string()
}
