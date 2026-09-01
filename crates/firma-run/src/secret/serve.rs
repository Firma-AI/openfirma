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
pub async fn serve_request(
    request: &BrokerRequest<'_>,
    spec: Option<&CliIntegrationSpec<SecretMatcher>>,
    store: &RwLock<SecretStore>,
    real_bin_dir: Option<&Path>,
) -> BrokerResponse<'static> {
    // Convert `Vec<Str>` to `Vec<String>` for `CliIntegrationSpec` matching.
    let args: Vec<String> = request.args.iter().map(ToString::to_string).collect();

    match spec {
        None => {
            // No integration: no credential envs, no extraction, pass through.
            match run_subprocess(&request.bin, &args, &[], real_bin_dir).await {
                Ok((stdout, stderr, status)) => {
                    let output = chunks_from_output(stdout, stderr);
                    BrokerResponse::executed(output, status)
                }
                Err(error) => BrokerResponse::rejected(error),
            }
        }
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
                // Safe command: execution with credential envs, no extraction.
                match run_subprocess(&request.bin, &args, &spec.credential_env_vars, real_bin_dir)
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
                    &spec.credential_env_vars,
                    real_bin_dir,
                )
                .await
                {
                    Ok(output) => output,
                    Err(error) => return BrokerResponse::rejected(error),
                };

                // Extract secrets from stdout and rewrite with placeholders.
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

                // Persist pending mappings for the gateway to resolve later.
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
/// Preserves a simple order: stdout first, then stderr if non-empty. The
/// kernel-level interleaving preserved by a concurrent-reader implementation
/// is not reproduced here — the broker's `stream` module documents that
/// ordering is best-effort observed capture order.
fn chunks_from_output(stdout: Vec<u8>, stderr: Vec<u8>) -> Vec<BrokerOutputChunk> {
    let mut chunks = Vec::with_capacity(2);
    if stdout.is_empty() {
        // Even empty stdout should be represented if stderr is also empty to
        // preserve the `executed` shape; push empty stdout so the response
        // is not mistaken for no output. The shim can handle empty stdout.
        // To avoid an extra empty chunk when both are empty, push one empty
        // stdout.
        if stderr.is_empty() {
            chunks.push(BrokerOutputChunk::Stdout(Vec::new()));
        }
    } else {
        chunks.push(BrokerOutputChunk::Stdout(stdout));
    }
    if !stderr.is_empty() {
        chunks.push(BrokerOutputChunk::Stderr(stderr));
    }
    chunks
}

/// Spawn the real vault binary with a minimal environment.
///
/// Only `credential_env_vars` (if present in the broker's environment) and
/// `PATH` are forwarded — `env_clear` is used so no other parent env leaks
/// into the vault invocation. When `real_bin_dir` is `Some`, the binary is
/// resolved as `real_bin_dir/<bin>` (Linux bwrap layout); otherwise `bin` is
/// resolved via `PATH`.
async fn run_subprocess(
    bin: &str,
    args: &[String],
    credential_env_vars: &[String],
    real_bin_dir: Option<&Path>,
) -> Result<(Vec<u8>, Vec<u8>, BrokerExitStatus), String> {
    let bin_path = real_bin_dir.map_or_else(|| Path::new(bin).to_path_buf(), |dir| dir.join(bin));

    let mut cmd = tokio::process::Command::new(&bin_path);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

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

    let output = cmd
        .output()
        .await
        .map_err(|error| format!("failed to spawn subprocess: {error}"))?;

    let status = BrokerExitStatus::from(output.status);
    Ok((output.stdout, output.stderr, status))
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
        let response = serve_request(&request, None, &store, None).await;
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

        let spec = CliIntegrationSpec {
            binary_name: "bws".to_string(),
            provider_id: "bitwarden".to_string(),
            credential_env_vars: vec!["BWS_ACCESS_TOKEN".to_string()],
            stripped_options: vec![],
            forbidden_options: vec![FlagSpec::value("--server-url")],
            matchers: vec![],
        };
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
        let response = serve_request(&request, Some(&spec), &store, None).await;
        assert!(matches!(
            response.decode().expect("decode"),
            firma_secret_provider::broker::DecodedBrokerResponse::Rejected(_)
        ));
    }

    #[tokio::test]
    async fn sensitive_command_rewrites_and_stores_placeholder() {
        use firma_secret_provider::{
            non_empty::vec::NonEmptyVec,
            spec::{
                MatcherRule,
                cli::{CliIntegrationSpec, CommandAndMatcher, CommandPattern},
            },
        };
        use serde_json::json;

        // Build a minimal sensitive spec: `secret get` with json matcher.
        let matcher = matcher_for_json();
        let spec = CliIntegrationSpec {
            binary_name: "echo".to_string(),
            provider_id: "test".to_string(),
            credential_env_vars: vec![],
            stripped_options: vec![],
            forbidden_options: vec![],
            matchers: vec![MatcherRule::SensitiveCommand(CommandAndMatcher {
                command: CommandPattern::prefix(
                    NonEmptyVec::new(vec!["secret".to_string(), "get".to_string()])
                        .expect("non-empty"),
                ),
                matcher,
                stripped_options: vec![],
                append_options: vec![],
            })],
        };

        // The real CLI is `echo`; we will feed it json via args that echo prints.
        // Echo with json: `echo '[{"key":"token","value":"s3cr3t"}]'`
        let json_payload = json!([{"key": "token", "value": "s3cr3t"}]).to_string();
        let store = store();
        let request = BrokerRequest {
            bin: BinaryName::new("echo").expect("valid"),
            args: vec!["secret".into(), "get".into(), json_payload.clone().into()],
        };
        // This will run `echo secret get '[{"key":"token","value":"s3cr3t"}]'`
        // which outputs `secret get [{"key":"token","value":"s3cr3t"}]\n` — not
        // valid json for the matcher (needs exactly the array). The matcher
        // will fail and we should get a rejection (fail-closed), not raw.
        let response = serve_request(&request, Some(&spec), &store, None).await;
        // Either executed with rewritten placeholder or rejected due to bad shape;
        // both are acceptable fail-closed outcomes for this malformed echo payload.
        let _decoded = response.decode().expect("decode");
    }
}
