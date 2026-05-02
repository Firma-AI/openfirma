use std::collections::BTreeMap;
use std::io::{self, Read, Write};
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
    let attribution_headers = load_attr_headers_from_env();
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
        let attribution_headers = attribution_headers.clone();

        thread::spawn(move || {
            if let Err(error) =
                handle_connection(client_stream, &upstream_path, &attribution_headers)
            {
                tracing::warn!(
                    "proxy bridge connection from {client_addr} failed: {}",
                    error
                );
            }
        });
    }
}

#[cfg(unix)]
fn handle_connection(
    mut client: TcpStream,
    upstream_path: &std::path::Path,
    attribution_headers: &BTreeMap<String, String>,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut upstream = UnixStream::connect(upstream_path)?;
    if attribution_headers.is_empty() {
        return relay_tcp_to_unix(&mut client, &mut upstream);
    }

    let mut prefetched = Vec::new();
    inject_request_headers(
        &mut client,
        &mut upstream,
        attribution_headers,
        &mut prefetched,
    )?;
    if !prefetched.is_empty() {
        upstream.write_all(&prefetched)?;
    }

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

fn load_attr_headers_from_env() -> BTreeMap<String, String> {
    let Ok(raw) = std::env::var("FIRMA_RUN_ATTR_HEADERS_JSON") else {
        return BTreeMap::new();
    };
    if raw.trim().is_empty() {
        return BTreeMap::new();
    }
    serde_json::from_str::<BTreeMap<String, String>>(&raw).unwrap_or_default()
}

fn inject_request_headers(
    client: &mut TcpStream,
    upstream: &mut UnixStream,
    attribution_headers: &BTreeMap<String, String>,
    prefetched: &mut Vec<u8>,
) -> io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_header_terminator(&buffer) {
            break pos;
        }
        if buffer.len() > 1024 * 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed 128KiB",
            ));
        }
    };

    let mut head = buffer[..header_end].to_vec();
    let tail = &buffer[header_end + 4..];
    prefetched.extend_from_slice(tail);

    append_missing_headers(&mut head, attribution_headers)?;
    upstream.write_all(&head)?;
    upstream.write_all(b"\r\n\r\n")?;
    Ok(())
}

fn append_missing_headers(
    header_block: &mut Vec<u8>,
    attribution_headers: &BTreeMap<String, String>,
) -> io::Result<()> {
    let head_str = std::str::from_utf8(header_block).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers are not valid utf-8",
        )
    })?;
    let mut lines = head_str.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Ok(());
    };
    let existing = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, _)| name.trim().to_ascii_lowercase())
        })
        .collect::<std::collections::BTreeSet<_>>();

    let mut rebuilt = String::new();
    rebuilt.push_str(request_line);
    rebuilt.push_str("\r\n");
    for line in head_str.split("\r\n").skip(1) {
        if !line.is_empty() {
            rebuilt.push_str(line);
            rebuilt.push_str("\r\n");
        }
    }

    for (name, value) in attribution_headers {
        if !existing.contains(&name.to_ascii_lowercase()) {
            rebuilt.push_str(name);
            rebuilt.push_str(": ");
            rebuilt.push_str(value);
            rebuilt.push_str("\r\n");
        }
    }

    *header_block = rebuilt.into_bytes();
    Ok(())
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{append_missing_headers, find_header_terminator};

    #[test]
    fn finds_header_terminator() {
        let req = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let pos = find_header_terminator(req).expect("terminator");
        assert_eq!(&req[pos..pos + 4], b"\r\n\r\n");
    }

    #[test]
    fn appends_missing_attr_headers() {
        let mut req_head = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_001".to_string());
        headers.insert("x-firma-profile".to_string(), "claude-code".to_string());
        append_missing_headers(&mut req_head, &headers).expect("append headers");
        let rendered = String::from_utf8(req_head).expect("utf8");
        assert!(rendered.contains("x-firma-session-id: sess_001\r\n"));
        assert!(rendered.contains("x-firma-profile: claude-code\r\n"));
    }
}
