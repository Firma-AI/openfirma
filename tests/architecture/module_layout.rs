//! Keep nested Rust modules in `module/mod.rs`, rather than splitting the
//! parent across `module.rs` and `module/`.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;

const IGNORED_DIRS: &[&str] = &[".git", ".jj", "node_modules", "target"];

#[test]
fn nested_modules_use_mod_rs() -> Result<(), Box<dyn std::error::Error>> {
    let graph = crate::metadata::load()?;
    let workspace_root = graph.workspace().root().as_std_path();
    let mut violations = Vec::new();

    collect_violations(workspace_root, workspace_root, &mut violations)?;
    violations.sort();

    assert!(
        violations.is_empty(),
        "nested module layout violations:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn collect_violations(
    workspace_root: &Path,
    dir: &Path,
    violations: &mut Vec<String>,
) -> io::Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            if !is_ignored_dir(&path) {
                collect_violations(workspace_root, &path, violations)?;
            }
            continue;
        }

        if !file_type.is_file()
            || path.extension() != Some(OsStr::new("rs"))
            || path.file_name() == Some(OsStr::new("mod.rs"))
        {
            continue;
        }

        let module_dir = path.with_extension("");
        if module_dir.is_dir() && contains_rust_sources(&module_dir)? {
            violations.push(format!(
                "- {} and {}/; move the parent module to {}/mod.rs",
                display_path(workspace_root, &path),
                display_path(workspace_root, &module_dir),
                display_path(workspace_root, &module_dir)
            ));
        }
    }

    Ok(())
}

fn contains_rust_sources(dir: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_file() && path.extension() == Some(OsStr::new("rs")) {
            return Ok(true);
        }

        if file_type.is_dir() && !is_ignored_dir(&path) && contains_rust_sources(&path)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn is_ignored_dir(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        IGNORED_DIRS
            .iter()
            .any(|ignored| name == OsStr::new(ignored))
    })
}

fn display_path(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .display()
        .to_string()
}
