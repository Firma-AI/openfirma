use std::io;
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::thread;

use crate::args::ProxyBridgeArgs;
use crate::error::RunError;

/// Run the internal sandbox bridge process.
///
/// The bridge accepts HTTP proxy traffic over TCP (inside the sandbox) and
/// relays bytes bidirectionally to a host-side Unix socket endpoint.
///
/// # Errors
///
/// Returns an error if the bridge cannot bind/listen or if the platform does
/// not support Unix sockets.
pub fn execute_proxy_bridge(args: &ProxyBridgeArgs) -> Result<i32, RunError> {
    #[cfg(unix)]
    {
        run_proxy_bridge_unix(args)?;
        Ok(0)
    }

    #[cfg(not(unix))]
    {
        let _ = args;
        Err(RunError::UnsupportedBackend {
            backend: "internal_proxy_bridge".to_string(),
            reason: "unix socket bridge is unavailable on non-unix hosts".to_string(),
        })
    }
}

#[cfg(unix)]
fn run_proxy_bridge_unix(args: &ProxyBridgeArgs) -> Result<(), RunError> {
    let listener = TcpListener::bind(args.listen).map_err(|error| {
        RunError::Spawn(format!(
            "failed to bind sandbox proxy bridge at {}: {error}",
            args.listen
        ))
    })?;

    loop {
        let (client_stream, client_addr) = listener
            .accept()
            .map_err(|error| RunError::Spawn(format!("proxy bridge accept failed: {error}")))?;
        let upstream_path = args.upstream_uds.clone();

        thread::spawn(move || {
            if let Err(error) = handle_connection(client_stream, &upstream_path) {
                tracing::warn!(
                    "proxy bridge connection from {client_addr} failed: {}",
                    error
                );
            }
        });
    }
}

#[cfg(unix)]
fn handle_connection(mut client: TcpStream, upstream_path: &std::path::Path) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut upstream = UnixStream::connect(upstream_path)?;
    relay_tcp_to_unix(&mut client, &mut upstream)
}

#[cfg(unix)]
fn relay_tcp_to_unix(client: &mut TcpStream, upstream: &mut UnixStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client.try_clone()?;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream.try_clone()?;

    let t1 = thread::spawn(move || io::copy(&mut client_read, &mut upstream_write));
    let t2 = thread::spawn(move || io::copy(&mut upstream_read, &mut client_write));

    let first = t1
        .join()
        .map_err(|_| io::Error::other("proxy bridge copy panic"))?;
    let second = t2
        .join()
        .map_err(|_| io::Error::other("proxy bridge copy panic"))?;

    first?;
    second?;
    Ok(())
}
