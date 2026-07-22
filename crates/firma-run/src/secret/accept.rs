//! Broker accept loop.
//!
//! Accepts shim connections from [`broker::BrokerListener`], asks the Sidecar for a
//! decision via an injected `decide` closure, and serves the result via
//! [`serve::serve_request`]. Each connection is handled synchronously (one thread per
//! connection is spawned by the caller if parallelism is needed). The decide
//! closure is PDP-agnostic; the real caller passes one that calls
//! [`pep::request_secret_decision`].

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;

use super::SecretStore;
use super::broker::{BrokerListener, BrokerRequest};
use super::integration::IntegrationSpec;
use super::pep::SecretPepOutcome;
use super::serve::serve_request;

/// Accept and serve shim connections until the listener is closed.
///
/// `decide(bin, args)` returns the PEP outcome for each launch. `spec_for(bin)`
/// looks up the integration spec for the binary. Both closures are shared across
/// threads. Per-connection errors are logged and do not stop the loop; the loop
/// ends when `accept_one` fails (typically when the listener is dropped).
pub fn serve_forever<D, S>(
    listener: BrokerListener,
    store: Arc<ArcSwap<SecretStore>>,
    decide: Arc<D>,
    spec_for: Arc<S>,
    real_bin_dir: Option<Arc<Path>>,
) where
    D: Fn(&str, &str) -> SecretPepOutcome + Send + Sync + 'static,
    S: Fn(&str) -> Option<IntegrationSpec> + Send + Sync + 'static,
{
    loop {
        let store = Arc::clone(&store);
        let decide = Arc::clone(&decide);
        let spec_for = Arc::clone(&spec_for);
        let real_bin_dir = real_bin_dir.clone();

        let result = listener.accept_one(|request: BrokerRequest| {
            let outcome = decide(&request.bin, &request.args);
            let spec = spec_for(&request.bin);
            let dir = real_bin_dir.as_deref();
            serve_request(&request, &outcome, spec.as_ref(), &store, dir)
        });

        match result {
            Ok(()) => {}
            Err(error) => {
                tracing::debug!(%error, "secret broker accept loop stopping");
                break;
            }
        }
    }
    drop((listener, store, decide, spec_for, real_bin_dir));
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    use super::*;
    use crate::secret::broker::BrokerResponse;

    fn call(path: &std::path::Path, bin: &str, args: &str) -> BrokerResponse {
        let mut stream = UnixStream::connect(path).expect("connect");
        let payload = serde_json::to_string(&crate::secret::broker::BrokerRequest {
            bin: bin.to_string(),
            args: args.to_string(),
        })
        .expect("serialize");
        stream
            .write_all(format!("{payload}\n").as_bytes())
            .expect("write");
        stream.flush().expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        serde_json::from_str(line.trim()).expect("deserialize")
    }

    #[test]
    fn passthrough_echo_end_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker.sock");
        let listener = BrokerListener::bind(&path).expect("bind");
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));

        let server = thread::spawn(move || {
            serve_forever(
                listener,
                store,
                Arc::new(|_bin: &str, _args: &str| SecretPepOutcome::Passthrough),
                Arc::new(|_bin: &str| None),
                None,
            );
        });

        let response = call(&path, "echo", "hello from broker");
        let stdout = response.into_stdout().expect("ok response");
        assert_eq!(stdout.trim_ascii_end(), b"hello from broker");

        drop(server);
    }

    #[test]
    fn deny_outcome_returns_error_response() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broker-deny.sock");
        let listener = BrokerListener::bind(&path).expect("bind");
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));

        let server = thread::spawn(move || {
            serve_forever(
                listener,
                store,
                Arc::new(|_bin: &str, _args: &str| SecretPepOutcome::Deny("blocked".to_string())),
                Arc::new(|_bin: &str| None),
                None,
            );
        });

        let response = call(&path, "echo", "hello");
        assert!(response.into_stdout().is_err());

        drop(server);
    }
}
