//! Runner for `firma policy` subcommands.

use std::process::ExitCode;

use crate::args::policy::{PolicyArgs, PolicyCommand};

pub fn run(args: &PolicyArgs) -> ExitCode {
    match args.command {
        PolicyCommand::List => list(),
    }
}

pub fn list() -> ExitCode {
    println!("Postures  (--posture):\n");
    for (name, desc) in POSTURES {
        println!("  {name:<28}  {desc}");
    }
    println!("\nMappings  (--mapping, repeatable):\n");
    for (name, desc) in MAPPINGS {
        println!("  {name:<28}  {desc}");
    }
    println!();
    ExitCode::SUCCESS
}

static POSTURES: &[(&str, &str)] = &[
    ("strict", "Default-deny + communication only (no code ops)"),
    ("dev", "Adds code.read/write, issues, package install"),
    (
        "dev-with-delete-watch",
        "Dev + code.destructive allowed (local-exec / delete-watch)",
    ),
];

static MAPPINGS: &[(&str, &str)] = &[
    (
        "anthropic",
        "api.anthropic.com — Anthropic Claude API (CONNECT, no MITM)",
    ),
    ("openai", "api.openai.com — OpenAI API (CONNECT, no MITM)"),
    (
        "github",
        "api.github.com — GitHub REST API (MITM for per-endpoint classification)",
    ),
    (
        "gmail",
        "gmail.googleapis.com — Gmail REST API (MITM for per-endpoint classification)",
    ),
    ("npm", "registry.npmjs.org — npm package registry"),
    ("pypi", "pypi.org, files.pythonhosted.org — PyPI"),
    (
        "cargo",
        "crates.io, static.crates.io — Rust package registry",
    ),
    (
        "stripe",
        "api.stripe.com — Stripe REST API (MITM optional — check SDK cert pinning first)",
    ),
    ("custom", "Empty template — fill in manually"),
];
