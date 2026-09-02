//! Per-request broker dispatch.
//!
//! Turns one shim request into a vault CLI execution plus an extraction
//! transform that extracts secrets and substitutes placeholders before the
//! output reaches the agent. Fail-closed: any classification or extraction
//! error returns a [`firma_secret_provider::broker::BrokerResponse::Rejected`]
//! instead of forwarding plaintext.

use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;

use firma_core::SecretMatcher;
use firma_http::Authority;
use firma_secret_provider::{
    CompiledMatcher, MatchingResolution, SecretPlaceholder, SecretString,
    broker::{BrokerExitStatus, BrokerOutputChunk, BrokerRequest, BrokerResponse},
    spec::cli::CliIntegrationSpec,
    store::SecretStore,
};
use tokio::io::AsyncReadExt as _;
use tokio::sync::RwLock;

/// Execute a broker request and return the appropriate [`BrokerResponse`].
///
/// `spec` is the CLI integration resolved for `request.bin` (`None` when the
/// binary has no integration — forward without credential envs and without
/// extraction). `store` is the shared run-scoped dictionary, also used by the
/// secret gateway.
///
/// `real_bin_dir`: if `Some`, the real binary is resolved as
/// `real_bin_dir/<bin>` rather than searched on `PATH`. This supports the Linux
/// bwrap layout where un-shimmed binaries live under a separate directory.
///
/// `capture_limit` is the per-stream raw byte cap applied while reading the
/// child's stdout/stderr. Output exceeding the cap is rejected (fail closed)
/// rather than buffered.
pub async fn serve_request(
    request: &BrokerRequest<'_>,
    spec: Option<&CliIntegrationSpec<SecretMatcher>>,
    store: &RwLock<SecretStore>,
    real_bin_dir: Option<&Path>,
    capture_limit: usize,
) -> BrokerResponse<'static> {
    let args: Vec<String> = request.args.iter().map(ToString::to_string).collect();

    match spec {
        None => BrokerResponse::rejected(format!("unconfigured binary {}", request.bin)),
        Some(spec) => match spec.resolve_args(&args) {
            MatchingResolution::Blocked => BrokerResponse::rejected(format!(
                "blocked command: {} {}",
                request.bin,
                request
                    .args
                    .iter()
                    .map(|s| s.as_ref())
                    .collect::<Vec<&str>>()
                    .join(" ")
            )),
            MatchingResolution::PassThrough => {
                match run_subprocess(
                    &request.bin,
                    &args,
                    spec.credential_env_vars(),
                    real_bin_dir,
                    capture_limit,
                )
                .await
                {
                    Ok((stdout, stderr, status)) => {
                        let output = chunks_from_output(stdout, stderr);
                        BrokerResponse::executed(output, status)
                    }
                    Err(error) => BrokerResponse::rejected(error),
                }
            }
            MatchingResolution::Matcher(matcher) => {
                let compiled = match CompiledMatcher::compile(matcher) {
                    Ok(compiled) => compiled,
                    Err(error) => {
                        return BrokerResponse::rejected(format!("matcher compile error: {error}"));
                    }
                };
                let rewritten_args = spec.rewrite_args(&args);
                let (stdout, stderr, status) = match run_subprocess(
                    &request.bin,
                    &rewritten_args,
                    spec.credential_env_vars(),
                    real_bin_dir,
                    capture_limit,
                )
                .await
                {
                    Ok(output) => output,
                    Err(error) => return BrokerResponse::rejected(error),
                };

                let mut pending: Vec<(SecretPlaceholder, HashSet<Authority>, SecretString)> =
                    Vec::new();
                let rewritten =
                    match compiled.rewrite(&stdout, &mut |_name, secret, domains, _item| {
                        let placeholder = SecretPlaceholder::new();
                        pending.push((placeholder.clone(), domains, secret));
                        placeholder
                    }) {
                        Ok(rewritten) => rewritten,
                        Err(error) => {
                            return BrokerResponse::rejected(format!(
                                "secret extraction failed: {error}"
                            ));
                        }
                    };

                if !pending.is_empty() {
                    let mut store = store.write().await;
                    for (placeholder, domains, secret) in pending {
                        store.insert(placeholder, domains, secret);
                    }
                }

                let output = chunks_from_output(rewritten, stderr);
                BrokerResponse::executed(output, status)
            }
        },
    }
}

/// Build stream-tagged output chunks from stdout/stderr.
///
/// At least one chunk is emitted when both streams are empty so the
/// `executed` shape is preserved; otherwise only non-empty streams are
/// emitted. Stdout is emitted before stderr. The kernel-level interleaving
/// preserved by a concurrent-reader implementation is not reproduced — the
/// broker's `stream` module documents that ordering is best-effort observed
/// capture order.
fn chunks_from_output(stdout: Vec<u8>, stderr: Vec<u8>) -> Vec<BrokerOutputChunk> {
    if stdout.is_empty() && stderr.is_empty() {
        return vec![BrokerOutputChunk::Stdout(Vec::new())];
    }
    let mut chunks = Vec::with_capacity(2);
    if !stdout.is_empty() {
        chunks.push(BrokerOutputChunk::Stdout(stdout));
    }
    if !stderr.is_empty() {
        chunks.push(BrokerOutputChunk::Stderr(stderr));
    }
    chunks
}

/// Spawn the real vault binary with a minimal environment and capture its
/// output, capped at `capture_limit` bytes per stream.
///
/// Only `credential_env_vars` (if present in the broker's environment) and
/// `PATH` are forwarded — `env_clear` is used so no other parent env leaks
/// into the vault invocation. On Windows, `SYSTEMROOT` and `PATHEXT` are also
/// forwarded because children without `SYSTEMROOT` commonly fail at startup.
/// `HOME` is deliberately absent on every platform: vault CLIs that require
/// config state under `$HOME` fail rather than read host files. When
/// `real_bin_dir` is `Some`, the binary is resolved as `real_bin_dir/<bin>`
/// (Linux bwrap layout); otherwise `bin` is resolved via `PATH`.
///
/// The child is killed if this future is dropped before it completes
/// (`kill_on_drop`), so a cancelled exchange (broker `operation_timeout`)
/// never leaves the real tool running out of the sandbox. Output above the
/// capture limit is rejected (fail closed) rather than truncated or buffered.
async fn run_subprocess(
    bin: &str,
    args: &[String],
    credential_env_vars: &[String],
    real_bin_dir: Option<&Path>,
    capture_limit: usize,
) -> Result<(Vec<u8>, Vec<u8>, BrokerExitStatus), String> {
    let bin_path = real_bin_dir.map_or_else(|| Path::new(bin).to_path_buf(), |dir| dir.join(bin));

    let mut cmd = tokio::process::Command::new(&bin_path);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true);

    cmd.env_clear();
    for var in credential_env_vars {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    #[cfg(windows)]
    for var in ["SYSTEMROOT", "PATHEXT"] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|error| format!("failed to spawn subprocess: {error}"))?;
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture subprocess stdout: pipe unavailable".to_string())?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture subprocess stderr: pipe unavailable".to_string())?;

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut out_chunk = vec![0u8; 8192];
    let mut err_chunk = vec![0u8; 8192];

    loop {
        if stdout_done && stderr_done {
            break;
        }
        tokio::select! {
            result = stdout_pipe.read(&mut out_chunk), if !stdout_done => {
                match result {
                    Ok(0) => stdout_done = true,
                    Ok(n) => {
                        stdout_buf.extend_from_slice(&out_chunk[..n]);
                        if stdout_buf.len() > capture_limit {
                            return Err(format!(
                                "tool stdout exceeded capture limit {capture_limit} bytes"
                            ));
                        }
                    }
                    Err(error) => return Err(format!("failed to read tool stdout: {error}")),
                }
            }
            result = stderr_pipe.read(&mut err_chunk), if !stderr_done => {
                match result {
                    Ok(0) => stderr_done = true,
                    Ok(n) => {
                        stderr_buf.extend_from_slice(&err_chunk[..n]);
                        if stderr_buf.len() > capture_limit {
                            return Err(format!(
                                "tool stderr exceeded capture limit {capture_limit} bytes"
                            ));
                        }
                    }
                    Err(error) => return Err(format!("failed to read tool stderr: {error}")),
                }
            }
        }
    }

    let status = child
        .wait()
        .await
        .map_err(|error| format!("failed to wait for subprocess: {error}"))?;
    let status = BrokerExitStatus::from(status);
    Ok((stdout_buf, stderr_buf, status))
}

#[cfg(test)]
mod tests {
    use firma_core::{SecretMatcher, SecretNameSource};
    use firma_secret_provider::{
        broker::{BinaryName, BrokerRequest},
        store::SecretStore,
    };
    use tokio::sync::RwLock;

    use super::serve_request;

    const CAPTURE_LIMIT: usize = 1024 * 1024;

    fn matcher_for_json() -> SecretMatcher {
        SecretMatcher::Json {
            record_path: "$[*]".to_string(),
            value_path: "$.value".to_string(),
            name: SecretNameSource::Path {
                path: "$.key".to_string(),
            },
            item_selector: None,
            domain_selector: None,
        }
    }

    fn store() -> RwLock<SecretStore> {
        RwLock::new(SecretStore::new())
    }

    #[tokio::test]
    async fn passthrough_without_spec_returns_raw_stdout() {
        let store = store();
        let request = BrokerRequest {
            bin: BinaryName::new("echo").expect("valid bin"),
            args: vec!["hello".into(), "from".into(), "broker".into()],
        };
        let response = serve_request(&request, None, &store, None, CAPTURE_LIMIT).await;
        let decoded = response.decode().expect("decode");
        match decoded {
            firma_secret_provider::broker::DecodedBrokerResponse::Executed(output) => {
                let stdout: Vec<u8> = output
                    .output
                    .into_iter()
                    .filter_map(|c| match c {
                        firma_secret_provider::broker::BrokerOutputChunk::Stdout(b) => Some(b),
                        firma_secret_provider::broker::BrokerOutputChunk::Stderr(_) => None,
                    })
                    .flatten()
                    .collect();
                assert_eq!(stdout, b"hello from broker\n");
            }
            firma_secret_provider::broker::DecodedBrokerResponse::Rejected(e) => {
                panic!("expected executed, got rejected: {e}");
            }
        }
    }

    #[tokio::test]
    async fn blocked_forbidden_option_is_rejected() {
        use firma_config_schema::secret_provider::cli::FlagSpec;
        use firma_secret_provider::spec::cli::CliIntegrationSpec;

        let spec = CliIntegrationSpec::new(
            "bws".to_string(),
            "bitwarden".to_string(),
            vec!["BWS_ACCESS_TOKEN".to_string()],
            vec![],
            vec![FlagSpec::value("--server-url")],
            vec![],
        )
        .unwrap_or_else(|error| panic!("valid spec: {error}"));
        let store = store();
        let request = BrokerRequest {
            bin: BinaryName::new("bws").expect("valid"),
            args: vec![
                "secret".into(),
                "get".into(),
                "x".into(),
                "--server-url".into(),
                "https://evil".into(),
            ],
        };
        let response = serve_request(&request, Some(&spec), &store, None, CAPTURE_LIMIT).await;
        assert!(matches!(
            response.decode().expect("decode"),
            firma_secret_provider::broker::DecodedBrokerResponse::Rejected(_)
        ));
    }

    #[tokio::test]
    async fn sensitive_command_extracts_and_stores_placeholder() {
        use firma_secret_provider::{
            non_empty::vec::NonEmptyVec,
            spec::{
                MatcherRule,
                cli::{CliIntegrationSpec, CommandAndMatcher, CommandPattern},
            },
        };
        use serde_json::json;

        let matcher = matcher_for_json();
        let payload = json!([{"key": "token", "value": "s3cr3t"}]).to_string();
        let spec = CliIntegrationSpec::new(
            "echo".to_string(),
            "test".to_string(),
            vec![],
            vec![],
            vec![],
            vec![MatcherRule::SensitiveCommand(CommandAndMatcher {
                command: CommandPattern::prefix(
                    NonEmptyVec::new(vec![payload.clone()]).expect("non-empty"),
                ),
                matcher,
                stripped_options: vec![],
                append_options: vec![],
            })],
        )
        .unwrap_or_else(|error| panic!("valid spec: {error}"));
        let store = RwLock::new(SecretStore::new());
        let request = BrokerRequest {
            bin: BinaryName::new("echo").expect("valid"),
            args: vec![payload.clone().into()],
        };
        let response = serve_request(&request, Some(&spec), &store, None, CAPTURE_LIMIT).await;
        let decoded = response.decode().expect("decode");
        let firma_secret_provider::broker::DecodedBrokerResponse::Executed(output) = decoded else {
            panic!("expected executed, got {decoded:?}");
        };
        let stdout: Vec<u8> = output
            .output
            .into_iter()
            .filter_map(|c| match c {
                firma_secret_provider::broker::BrokerOutputChunk::Stdout(b) => Some(b),
                firma_secret_provider::broker::BrokerOutputChunk::Stderr(_) => None,
            })
            .flatten()
            .collect();
        let text = String::from_utf8(stdout).expect("stdout utf-8");
        assert!(
            !text.contains("s3cr3t"),
            "rewritten stdout must not contain the raw secret: {text}"
        );
        assert!(
            text.contains("fsp_"),
            "rewritten stdout must contain a placeholder: {text}"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(text.trim()).expect("rewritten stdout is valid json");
        let placeholder = parsed[0]["value"]
            .as_str()
            .expect("value is a string placeholder");
        assert!(
            placeholder.starts_with("fsp_"),
            "placeholder prefix: {placeholder}"
        );
        assert_eq!(store.read().await.len(), 1, "one secret must be stored");
    }

    #[tokio::test]
    async fn capture_limit_rejects_oversized_output() {
        let store = store();
        let request = BrokerRequest {
            bin: BinaryName::new("echo").expect("valid bin"),
            args: vec!["hello".into(), "from".into(), "broker".into()],
        };
        let tiny_limit = 4usize;
        let response = serve_request(&request, None, &store, None, tiny_limit).await;
        assert!(
            matches!(
                response.decode().expect("decode"),
                firma_secret_provider::broker::DecodedBrokerResponse::Rejected(reason) if reason.contains("capture limit")
            ),
            "oversized output must be rejected with a capture-limit message"
        );
    }
}
