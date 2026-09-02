#![allow(dead_code, reason = "Code will be used in later iteration")]

//! Broker accept loop.
//!
//! Accepts shim connections from [`firma_secret_provider::broker::server::BrokerListener`]
//! and serves each one via [`serve::serve_request`]. Each connection is handled
//! synchronously in the accept loop; callers that need parallelism should
//! spawn this future per listener or wrap the loop with `tokio::spawn`.
//! A binary only ever reaches this loop because it matched a configured
//! secret-provider entry (that's why the shim was installed over it), so
//! there is no separate decision to make here — every launch is mediated
//! through the integration's `resolve_args` classification.

use std::path::Path;
use std::sync::Arc;

use firma_core::SecretMatcher;
use firma_secret_provider::{
    broker::server::{AcceptError, BrokerListener},
    spec::cli::CliIntegrationSpec,
    store::SecretStore,
};
use tokio::sync::RwLock;

use super::serve::serve_request;

/// Accept and serve shim connections until the listener is closed.
///
/// `spec_for(bin)` looks up the [`CliIntegrationSpec`] for the binary and is
/// shared across tasks. `store` is the run-scoped [`SecretStore`] dictionary
/// (shared with the secret gateway). `real_bin_dir`, when `Some`, overrides
/// `PATH` lookup for the real binary (Linux bwrap layout). Per-connection
/// handler errors are mapped to [`firma_secret_provider::broker::BrokerResponse::Rejected`];
/// only listener-level [`AcceptError::Listener`] errors stop the loop. Per-
/// connection [`AcceptError::Connection`] errors (timeout, malformed framing,
/// I/O failure, rejected peer credentials) are logged and the loop continues.
/// This future never returns a `Result` — it loops until the listener can no
/// longer accept and then returns `()`.
pub async fn serve_forever<S>(
    listener: BrokerListener,
    store: Arc<RwLock<SecretStore>>,
    spec_for: Arc<S>,
    real_bin_dir: Option<Arc<Path>>,
) where
    S: Fn(&str) -> Option<CliIntegrationSpec<SecretMatcher>> + Send + Sync + 'static,
{
    let capture_limit = listener.config().max_response_size() / 4;
    loop {
        let store = Arc::clone(&store);
        let spec_for = Arc::clone(&spec_for);
        let real_bin_dir = real_bin_dir.clone();

        let result = listener
            .accept_one(async |request| {
                let spec = spec_for(&request.bin);
                let dir = real_bin_dir.as_deref();
                serve_request(&request, spec.as_ref(), &store, dir, capture_limit).await
            })
            .await;

        match result {
            Ok(()) => {}
            Err(AcceptError::Connection(error)) => {
                tracing::warn!(%error, "secret broker connection failed; continuing to accept");
            }
            Err(AcceptError::Listener(error)) => {
                tracing::error!(%error, "secret broker listener failed; accept loop stopping");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use firma_config_schema::broker::BrokerConfig;
    use firma_secret_provider::{endpoint::server::ServerEndpoint, store::SecretStore};
    use tokio::sync::RwLock;

    use super::serve_forever;
    use firma_secret_provider::broker::server::BrokerListener;

    async fn bind_tcp() -> (BrokerListener, std::net::SocketAddr) {
        let endpoint = ServerEndpoint::from_str("tcp://127.0.0.1:0").expect("valid endpoint");
        let config = BrokerConfig::default();
        let listener = BrokerListener::bind(&endpoint, config).await.expect("bind");
        let bound = listener.bound_endpoint().expect("bound");
        let addr = match bound {
            firma_secret_provider::endpoint::EndpointInner::Tcp(addr) => addr,
            #[cfg(unix)]
            firma_secret_provider::endpoint::EndpointInner::Unix(_) => panic!("expected tcp"),
        };
        (listener, addr)
    }

    fn echo_spec() -> firma_secret_provider::spec::cli::CliIntegrationSpec<firma_core::SecretMatcher>
    {
        use firma_secret_provider::{
            non_empty::NonEmptyVec,
            spec::{MatcherRule, cli::CommandPattern},
        };

        // Exact `SafeCommand` on the whole argv so `echo` is classified as a
        // known-safe passthrough (unconfigured binaries are rejected now).
        firma_secret_provider::spec::cli::CliIntegrationSpec::new(
            "echo".to_string(),
            "echo".to_string(),
            vec![],
            vec![],
            vec![],
            vec![MatcherRule::SafeCommand(CommandPattern::exact(
                NonEmptyVec::new(vec![
                    String::from("hello"),
                    String::from("from"),
                    String::from("broker"),
                ])
                .expect("non-empty argv"),
            ))],
        )
        .unwrap_or_else(|error| panic!("valid spec: {error}"))
    }

    #[tokio::test]
    async fn echo_end_to_end() {
        let (listener, addr) = bind_tcp().await;
        let store = Arc::new(RwLock::new(SecretStore::new()));

        let spec = echo_spec();
        let server = tokio::spawn(serve_forever(
            listener,
            Arc::clone(&store),
            Arc::new(move |_bin: &str| Some(spec.clone())),
            None,
        ));

        let client_endpoint = firma_secret_provider::endpoint::client::ClientEndpoint::from_str(
            &format!("tcp://{addr}"),
        )
        .expect("valid client endpoint");
        let client = firma_secret_provider::broker::client::BrokerClient::new(
            client_endpoint,
            BrokerConfig::default(),
        );
        let output = client
            .run("echo", &["hello", "from", "broker"])
            .await
            .expect("run");
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

        // Dropping the server task stops the listener
        server.abort();
    }

    #[tokio::test]
    async fn blocked_command_is_rejected() {
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
        let (listener, addr) = bind_tcp().await;
        let store = Arc::new(RwLock::new(SecretStore::new()));
        let spec_clone = spec.clone();
        let server = tokio::spawn(serve_forever(
            listener,
            Arc::clone(&store),
            Arc::new(move |bin: &str| {
                if bin == "bws" {
                    Some(spec_clone.clone())
                } else {
                    None
                }
            }),
            None,
        ));
        let client_endpoint = firma_secret_provider::endpoint::client::ClientEndpoint::from_str(
            &format!("tcp://{addr}"),
        )
        .expect("valid");
        let client = firma_secret_provider::broker::client::BrokerClient::new(
            client_endpoint,
            BrokerConfig::default(),
        );
        let result = client
            .run(
                "bws",
                &["secret", "get", "x", "--server-url", "https://evil"],
            )
            .await;
        assert!(matches!(
            result,
            Err(firma_secret_provider::broker::client::error::BrokerClientError::Rejected(_))
        ));
        server.abort();
    }
}
