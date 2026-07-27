//! Per-request broker dispatch.
//!
//! Turns one shim request into a vault CLI execution plus an intercept
//! transform that extracts secrets and substitutes placeholders before the
//! output reaches the agent. This module owns the **routing**: it builds the
//! [`broker::BrokerResponse`] for a launch.
//!
//! A binary only ever reaches the broker because it matched a configured
//! secret-provider entry (that's why the shim was installed over it), so
//! being asked to serve a request is itself the authorization — every launch
//! runs with the integration spec's credential envs and extractor applied.

use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

use arc_swap::ArcSwap;

use super::SecretStore;
use super::broker::{BrokerRequest, BrokerResponse};
use firma_secret_provider::CliIntegrationSpec;

use super::intercept::intercept;

/// Errors from executing a vault CLI subprocess.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("failed to spawn subprocess: {0}")]
    Spawn(io::Error),
    #[error("subprocess wait failed: {0}")]
    Wait(io::Error),
    #[error(transparent)]
    Intercept(#[from] super::intercept::InterceptError),
}

/// Execute a broker request and return the appropriate [`BrokerResponse`].
///
/// Runs `spec`'s credential envs, applies its extractor, mints placeholders
/// into `store`, and returns the rewritten stdout. When `spec` is `None` (no
/// integration spec resolved for the binary), runs with no credential envs
/// and forwards stdout unmodified.
///
/// `real_bin_dir`: if `Some`, the real binary is resolved as
/// `real_bin_dir/<bin>` rather than searched on PATH. This supports the Linux
/// bwrap layout where un-shimmed binaries live under a separate directory.
pub fn serve_request(
    request: &BrokerRequest,
    spec: Option<&CliIntegrationSpec>,
    store: &ArcSwap<SecretStore>,
    real_bin_dir: Option<&Path>,
) -> BrokerResponse {
    match serve_inner(request, spec, store, real_bin_dir) {
        Ok(response) => response,
        Err(err) => BrokerResponse::err(err.to_string()),
    }
}

fn serve_inner(
    request: &BrokerRequest,
    spec: Option<&CliIntegrationSpec>,
    store: &ArcSwap<SecretStore>,
    real_bin_dir: Option<&Path>,
) -> Result<BrokerResponse, ServeError> {
    const EMPTY: &[String] = &[];
    let credential_env_vars = spec.map_or(EMPTY, |s| s.credential_env_vars.as_slice());
    let (strip_flags, forced_args) = spec.map_or((EMPTY, EMPTY), |s| {
        (s.strip_arg_flags.as_slice(), s.forced_args.as_slice())
    });
    let stdout = run_subprocess(
        request,
        credential_env_vars,
        real_bin_dir,
        strip_flags,
        forced_args,
    )?;
    if let Some(spec) = spec {
        let rewritten = intercept(&spec.matcher, &stdout, &spec.placeholder_template, store)?;
        Ok(BrokerResponse::ok(&rewritten))
    } else {
        Ok(BrokerResponse::ok(&stdout))
    }
}

/// Strip `--flag value` / `--flag=value` pairs from `args_str`, then append
/// `forced`. Used to ensure the subprocess always emits the format the matcher
/// expects, regardless of what format flags the agent passed to the shim.
fn normalize_args(args_str: &str, strip_flags: &[String], forced: &[String]) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut skip_next = false;
    for token in args_str.split_whitespace() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if strip_flags
            .iter()
            .any(|f| token == f.as_str() || token.starts_with(&format!("{f}=")))
        {
            // Two-token form "--flag value": skip this token and the next.
            // One-token form "--flag=value": skip only this token.
            if !token.contains('=') {
                skip_next = true;
            }
            continue;
        }
        result.push(token.to_owned());
    }
    result.extend(forced.iter().cloned());
    result
}

fn run_subprocess(
    request: &BrokerRequest,
    credential_env_vars: &[String],
    real_bin_dir: Option<&Path>,
    strip_flags: &[String],
    forced_args: &[String],
) -> Result<Vec<u8>, ServeError> {
    let bin_path = real_bin_dir.map_or_else(
        || Path::new(&request.bin).to_path_buf(),
        |dir| dir.join(&request.bin),
    );

    let args = normalize_args(&request.args, strip_flags, forced_args);

    let mut cmd = Command::new(&bin_path);
    cmd.args(&args).stdout(Stdio::piped()).stderr(Stdio::null());

    // Forward only the specified credential env vars from the broker's env.
    cmd.env_clear();
    for var in credential_env_vars {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }
    // Always forward PATH so the subprocess can find its own helpers.
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }

    let output = cmd.output().map_err(ServeError::Spawn)?;
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_store() -> ArcSwap<SecretStore> {
        ArcSwap::from_pointee(SecretStore::new())
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn normalize_args_strips_two_token_flag_and_appends_forced() {
        let result = normalize_args(
            "item get MyItem --format yaml",
            &s(&["--format"]),
            &s(&["--format", "json"]),
        );
        assert_eq!(result, ["item", "get", "MyItem", "--format", "json"]);
    }

    #[test]
    fn normalize_args_strips_equals_form_flag() {
        let result = normalize_args(
            "item get MyItem --format=yaml",
            &s(&["--format"]),
            &s(&["--format", "json"]),
        );
        assert_eq!(result, ["item", "get", "MyItem", "--format", "json"]);
    }

    #[test]
    fn normalize_args_handles_empty_args_and_no_strips() {
        assert_eq!(normalize_args("", &[], &[]), Vec::<String>::new());
        assert_eq!(normalize_args("item get x", &[], &[]), ["item", "get", "x"]);
    }

    #[test]
    fn normalize_args_strips_vault_dash_format() {
        let result = normalize_args(
            "kv get -format=json secret/path",
            &s(&["-format", "--format"]),
            &[],
        );
        assert_eq!(result, ["kv", "get", "secret/path"]);
    }

    #[test]
    fn runs_real_binary_and_returns_raw_stdout_without_spec() {
        let request = BrokerRequest {
            bin: "echo".to_string(),
            args: "raw".to_string(),
        };
        let store = empty_store();
        let response = serve_request(&request, None, &store, None);
        let stdout = response.into_stdout().expect("ok");
        assert_eq!(stdout.trim_ascii_end(), b"raw");
    }
}
