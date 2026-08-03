//! Keeps the `firma::integration` target at the external CLI boundary.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

const PRODUCTION_CRATES: &[&str] = &[
    "firma_authority",
    "firma_config_loader",
    "firma_core",
    "firma_fs",
    "firma_http",
    "firma_protobuf",
    "firma_run",
    "firma_runtime_state",
    "firma_secret_provider",
    "firma_sidecar",
    "firma_stack",
    "firma_tui",
];

#[test]
fn firma_integration_tests_use_only_the_cli_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let graph = crate::metadata::load()?;
    let workspace_root = graph.workspace().root();
    let tests_dir = workspace_root.join("crates/firma/tests/integration");
    let mut violations = Vec::new();
    let main_path = tests_dir.join("main.rs");
    let main_source = fs::read_to_string(&main_path)?;
    let main_tokens = main_source.parse::<TokenStream>()?;
    let declared_modules = declared_modules(&main_tokens);
    let mut test_modules = BTreeSet::new();

    for entry in fs::read_dir(&tests_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            violations.push(format!(
                "{} is a nested directory; firma CLI black-box tests must remain flat",
                display_path(workspace_root.as_std_path(), &path)
            ));
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }

        let source = fs::read_to_string(&path)?;
        let tokens = source.parse::<TokenStream>()?;
        let is_main = path.file_name().is_some_and(|name| name == "main.rs");
        if contains_include_macro(&tokens) || contains_path_attribute(&tokens) {
            violations.push(format!(
                "{} loads an external Rust source file",
                display_path(workspace_root.as_std_path(), &path)
            ));
        }
        if !is_main && contains_module_declaration(&tokens) {
            violations.push(format!(
                "{} declares a nested module; firma CLI black-box tests must remain flat",
                display_path(workspace_root.as_std_path(), &path)
            ));
        }
        if contains_macro_definition(&tokens) {
            violations.push(format!(
                "{} defines a macro, which could hide an unused CLI reference",
                display_path(workspace_root.as_std_path(), &path)
            ));
        }
        if !is_main && !contains_cli_binary_reference(&tokens) {
            violations.push(format!(
                "{} does not launch the compiled firma executable",
                display_path(workspace_root.as_std_path(), &path)
            ));
        }

        for crate_name in referenced_production_crates(&tokens) {
            violations.push(format!(
                "{} references production crate `{crate_name}` directly",
                display_path(workspace_root.as_std_path(), &path)
            ));
        }

        if !is_main {
            let module = path
                .file_stem()
                .and_then(|name| name.to_str())
                .ok_or("non-UTF-8 black-box test module name")?;
            test_modules.insert(module.to_string());
            if !declared_modules.contains(module) {
                violations.push(format!(
                    "{} is not declared by crates/firma/tests/integration/main.rs",
                    display_path(workspace_root.as_std_path(), &path)
                ));
            }
        }
    }

    for module in declared_modules.difference(&test_modules) {
        violations.push(format!(
            "crates/firma/tests/integration/main.rs declares missing module `{module}`"
        ));
    }

    assert!(
        violations.is_empty(),
        "firma CLI black-box test violations:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn referenced_production_crates(tokens: &TokenStream) -> BTreeSet<String> {
    let mut references = BTreeSet::new();
    inspect_tokens(tokens, &mut |token| {
        if let TokenTree::Ident(identifier) = token {
            let identifier = identifier.to_string();
            let identifier = identifier.strip_prefix("r#").unwrap_or(&identifier);
            if PRODUCTION_CRATES.contains(&identifier) {
                references.insert(identifier.to_string());
            }
        }
    });
    references
}

fn declared_modules(tokens: &TokenStream) -> BTreeSet<String> {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens
        .windows(3)
        .filter_map(|window| match window {
            [
                TokenTree::Ident(keyword),
                TokenTree::Ident(module),
                TokenTree::Punct(end),
            ] if keyword == "mod" && end.as_char() == ';' => Some(module.to_string()),
            _ => None,
        })
        .collect()
}

fn contains_cli_binary_reference(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    if tokens.windows(3).any(|window| match window {
        [TokenTree::Ident(macro_name), TokenTree::Punct(bang), TokenTree::Group(arguments)]
            if macro_name == "env" && bang.as_char() == '!' =>
        {
            arguments
                .stream()
                .into_iter()
                .any(|token| matches!(token, TokenTree::Literal(literal) if literal.to_string().contains("CARGO_BIN_EXE_firma")))
        }
        _ => false,
    }) {
        return true;
    }

    tokens.into_iter().any(|token| {
        matches!(token, TokenTree::Group(group) if contains_cli_binary_reference(&group.stream()))
    })
}

fn contains_include_macro(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.windows(2).any(|window| {
        matches!(window, [TokenTree::Ident(name), TokenTree::Punct(bang)] if name == "include" && bang.as_char() == '!')
    }) || tokens.into_iter().any(|token| {
        matches!(token, TokenTree::Group(group) if contains_include_macro(&group.stream()))
    })
}

fn contains_module_declaration(tokens: &TokenStream) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        TokenTree::Ident(identifier) => identifier == "mod",
        TokenTree::Group(group) => contains_module_declaration(&group.stream()),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

fn contains_macro_definition(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.windows(2).any(|window| {
        matches!(window, [TokenTree::Ident(name), TokenTree::Punct(bang)] if name == "macro_rules" && bang.as_char() == '!')
    }) || tokens.into_iter().any(|token| {
        matches!(token, TokenTree::Group(group) if contains_macro_definition(&group.stream()))
    })
}

fn contains_path_attribute(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.windows(2).any(|window| match window {
        [TokenTree::Punct(hash), TokenTree::Group(attribute)]
            if hash.as_char() == '#' && attribute.delimiter() == Delimiter::Bracket =>
        {
            contains_path_assignment(&attribute.stream())
        }
        _ => false,
    }) || tokens.into_iter().any(|token| {
        matches!(token, TokenTree::Group(group) if contains_path_attribute(&group.stream()))
    })
}

fn contains_path_assignment(tokens: &TokenStream) -> bool {
    let tokens = tokens.clone().into_iter().collect::<Vec<_>>();
    tokens.windows(2).any(|window| {
        matches!(window, [TokenTree::Ident(name), TokenTree::Punct(equals)] if name == "path" && equals.as_char() == '=')
    }) || tokens.into_iter().any(|token| {
        matches!(token, TokenTree::Group(group) if contains_path_assignment(&group.stream()))
    })
}

fn inspect_tokens(tokens: &TokenStream, inspect: &mut impl FnMut(&TokenTree)) {
    for token in tokens.clone() {
        inspect(&token);
        if let TokenTree::Group(group) = token {
            inspect_tokens(&group.stream(), inspect);
        }
    }
}

fn display_path(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[test]
fn production_reference_detection_handles_aliases_macros_and_comments() {
    let source = r#"
        // firma_core::ignored_comment()
        const TEXT: &str = "firma_stack::ignored_string()";
        extern crate firma_sidecar as sidecar;
        use firma_run::{
            routing as routes,
        };
        use r#firma_core as core;
        assert!(firma_runtime_state::runtime_paths::default_runtime_dir().exists());
    "#;
    let tokens = source.parse::<TokenStream>().expect("parse fixture");

    assert_eq!(
        referenced_production_crates(&tokens),
        BTreeSet::from([
            "firma_core".to_string(),
            "firma_run".to_string(),
            "firma_runtime_state".to_string(),
            "firma_sidecar".to_string(),
        ])
    );
}

#[test]
fn cli_binary_detection_requires_an_env_macro() {
    let comment_and_string = r#"
        // env!("CARGO_BIN_EXE_firma")
        const TEXT: &str = "CARGO_BIN_EXE_firma";
    "#;
    let actual_reference = r#"Command::new(env!("CARGO_BIN_EXE_firma"));"#;

    assert!(!contains_cli_binary_reference(
        &comment_and_string.parse().expect("parse fixture")
    ));
    assert!(contains_cli_binary_reference(
        &actual_reference.parse().expect("parse fixture")
    ));
}

#[test]
fn external_source_and_nested_module_detection_closes_scanner_bypasses() {
    assert!(contains_include_macro(
        &r#"include!("support.rs");"#.parse().expect("parse fixture")
    ));
    assert!(contains_path_attribute(
        &r#"#[path = "support.rs"] mod support;"#
            .parse()
            .expect("parse fixture")
    ));
    assert!(contains_module_declaration(
        &"mod support { fn helper() {} }"
            .parse()
            .expect("parse fixture")
    ));
}

#[test]
fn macro_definition_detection_rejects_hidden_cli_reference() {
    let source = r#"macro_rules! unused { () => { env!("CARGO_BIN_EXE_firma") } }"#;
    let tokens = source.parse().expect("parse fixture");

    assert!(contains_cli_binary_reference(&tokens));
    assert!(contains_macro_definition(&tokens));
}

#[test]
fn module_detection_handles_attributes() {
    let source = "mod always; #[cfg(unix)] mod on_unix;";

    assert_eq!(
        declared_modules(&source.parse().expect("parse fixture")),
        BTreeSet::from(["always".to_string(), "on_unix".to_string()])
    );
}
