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

use firma_secret_provider::CliIntegrationSpec;

use super::SecretStore;
use super::broker::{BrokerListener, BrokerRequest};
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
    S: Fn(&str) -> Option<CliIntegrationSpec> + Send + Sync + 'static,
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
    use std::net::{SocketAddr, TcpStream};
    use std::thread;

    use super::*;
    use crate::config::CommandMediatorEndpoint;
    use crate::secret::broker::BrokerResponse;

    fn bind_tcp() -> (BrokerListener, SocketAddr) {
        let endpoint = CommandMediatorEndpoint::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid addr"),
        };
        let listener = BrokerListener::bind(&endpoint).expect("bind");
        let CommandMediatorEndpoint::Tcp { addr } =
            listener.bound_endpoint().expect("bound_endpoint")
        else {
            panic!("TCP listener must return TCP endpoint");
        };
        (listener, addr)
    }

    fn call(addr: SocketAddr, bin: &str, args: &str) -> BrokerResponse {
        let mut stream = TcpStream::connect(addr).expect("connect");
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
        let (listener, addr) = bind_tcp();
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

        let response = call(addr, "echo", "hello from broker");
        let stdout = response.into_stdout().expect("ok response");
        assert_eq!(stdout.trim_ascii_end(), b"hello from broker");

        drop(server);
    }

    #[test]
    fn deny_outcome_returns_error_response() {
        let (listener, addr) = bind_tcp();
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

        let response = call(addr, "echo", "hello");
        assert!(response.into_stdout().is_err());

        drop(server);
    }
}
