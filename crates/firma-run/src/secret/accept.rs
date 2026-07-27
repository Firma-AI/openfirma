//! Broker accept loop.
//!
//! Accepts shim connections from [`broker::BrokerListener`] and serves each
//! one via [`serve::serve_request`]. Each connection is handled synchronously
//! (one thread per connection is spawned by the caller if parallelism is
//! needed). A binary only ever reaches this loop because it matched a
//! configured secret-provider entry (that's why the shim was installed over
//! it), so there is no separate decision to make here — every launch is
//! mediated.

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;

use firma_secret_provider::CliIntegrationSpec;

use super::SecretStore;
use super::broker::{BrokerListener, BrokerRequest};
use super::serve::serve_request;

/// Accept and serve shim connections until the listener is closed.
///
/// `spec_for(bin)` looks up the integration spec for the binary and is shared
/// across threads. Per-connection errors are logged and do not stop the
/// loop; the loop ends when `accept_one` fails (typically when the listener
/// is dropped).
pub fn serve_forever<S>(
    listener: BrokerListener,
    store: Arc<ArcSwap<SecretStore>>,
    spec_for: Arc<S>,
    real_bin_dir: Option<Arc<Path>>,
) where
    S: Fn(&str) -> Option<CliIntegrationSpec> + Send + Sync + 'static,
{
    loop {
        let store = Arc::clone(&store);
        let spec_for = Arc::clone(&spec_for);
        let real_bin_dir = real_bin_dir.clone();

        let result = listener.accept_one(|request: BrokerRequest| {
            let spec = spec_for(&request.bin);
            let dir = real_bin_dir.as_deref();
            serve_request(&request, spec.as_ref(), &store, dir)
        });

        match result {
            Ok(()) => {}
            Err(error) => {
                tracing::debug!(%error, "secret broker accept loop stopping");
                break;
            }
        }
    }
    drop((listener, store, spec_for, real_bin_dir));
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
    fn echo_end_to_end() {
        let (listener, addr) = bind_tcp();
        let store = Arc::new(ArcSwap::from_pointee(SecretStore::new()));

        let server = thread::spawn(move || {
            serve_forever(listener, store, Arc::new(|_bin: &str| None), None);
        });

        let response = call(addr, "echo", "hello from broker");
        let stdout = response.into_stdout().expect("ok response");
        assert_eq!(stdout.trim_ascii_end(), b"hello from broker");

        drop(server);
    }
}
