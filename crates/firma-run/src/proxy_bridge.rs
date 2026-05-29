#[cfg(any(unix, test))]
use std::collections::BTreeMap;
#[cfg(any(unix, test))]
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
#[cfg(unix)]
use std::thread;

use crate::error::RunError;

/// Lib-level input for [`execute_proxy_bridge`]. The CLI layer builds this
/// from its `clap`-derived args struct.
#[derive(Debug, Clone)]
pub struct ProxyBridgeInput {
    /// TCP listen address reachable by the sandboxed agent process.
    pub listen: std::net::SocketAddr,
    /// Upstream host-side Unix socket path exposed by `firma run`.
    pub upstream_uds: PathBuf,
}

/// Run the internal sandbox bridge process.
///
/// The bridge accepts HTTP proxy traffic over TCP (inside the sandbox) and
/// relays bytes bidirectionally to a host-side Unix socket endpoint.
///
/// # Errors
///
/// Returns an error if the bridge cannot bind/listen or if the platform does
/// not support Unix sockets.
pub fn execute_proxy_bridge(args: &ProxyBridgeInput) -> Result<i32, RunError> {
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
fn run_proxy_bridge_unix(args: &ProxyBridgeInput) -> Result<(), RunError> {
    let attribution_headers = load_attr_headers_from_env();
    let listener = TcpListener::bind(args.listen).map_err(|error| {
        RunError::Spawn(format!(
            "failed to bind sandbox proxy bridge at {}: {error}",
            args.listen
        ))
    })?;

    // Signal readiness after bind so the entrypoint script can start the agent
    // without a blind sleep. The entrypoint polls for this file's existence.
    if let Ok(dir) = std::env::var("FIRMA_RUN_RUNTIME_DIR") {
        let _ = std::fs::write(std::path::Path::new(&dir).join("proxy-bridge-ready"), []);
    }

    loop {
        let (client_stream, client_addr) = listener
            .accept()
            .map_err(|error| RunError::Spawn(format!("proxy bridge accept failed: {error}")))?;
        let upstream_path = args.upstream_uds.clone();
        let attribution_headers = attribution_headers.clone();
        let bridge_listen_addr = args.listen.to_string();

        thread::spawn(move || {
            if let Err(error) = handle_connection(
                client_stream,
                &upstream_path,
                &attribution_headers,
                &bridge_listen_addr,
            ) {
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
    bridge_listen_addr: &str,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    let mut upstream = UnixStream::connect(upstream_path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to reach host-side sidecar adapter at {}: {error}; \
sandbox clients may report connection failures via http://{bridge_listen_addr} (pre-sidecar mediation)",
                upstream_path.display()
            ),
        )
    })?;
    if attribution_headers.is_empty() {
        return relay_tcp_to_unix(&client, &upstream);
    }

    let mut upstream_read = upstream.try_clone()?;
    let mut client_write = client.try_clone()?;
    let response_copy = thread::spawn(move || io::copy(&mut upstream_read, &mut client_write));

    let forward_result =
        forward_requests_with_header_injection(&mut client, &mut upstream, attribution_headers);
    let reverse_result = response_copy
        .join()
        .map_err(|_| io::Error::other("proxy bridge response copy panic"))?;

    forward_result?;
    reverse_result?;
    Ok(())
}

#[cfg(unix)]
fn relay_tcp_to_unix(client: &TcpStream, upstream: &UnixStream) -> io::Result<()> {
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

#[cfg(unix)]
fn load_attr_headers_from_env() -> BTreeMap<String, String> {
    let Ok(raw) = std::env::var("FIRMA_RUN_ATTR_HEADERS_JSON") else {
        return BTreeMap::new();
    };
    if raw.trim().is_empty() {
        return BTreeMap::new();
    }
    serde_json::from_str::<BTreeMap<String, String>>(&raw).unwrap_or_default()
}

#[cfg(unix)]
fn forward_requests_with_header_injection(
    client: &mut TcpStream,
    upstream: &mut UnixStream,
    attribution_headers: &BTreeMap<String, String>,
) -> io::Result<()> {
    let mut buffer = Vec::new();
    loop {
        let header_end = read_until_header_block(client, &mut buffer)?;
        let Some(header_end) = header_end else {
            // EOF.
            return Ok(());
        };

        // Reuse allocation and avoid per-request copies.
        let mut request = std::mem::take(&mut buffer);
        let mut remaining = request.split_off(header_end + 4);
        request.truncate(header_end);

        let meta = parse_request_metadata(&request)?;
        append_missing_headers(&mut request, attribution_headers)?;

        // `request` already ends with \r\n (the CRLF of the last header
        // line). Write one more \r\n to complete the blank-line terminator.
        // Writing \r\n\r\n here would produce three CRLFs, injecting a
        // spurious blank line into the stream (e.g. into a CONNECT tunnel
        // before the TLS ClientHello, corrupting the TLS handshake).
        upstream.write_all(&request)?;
        upstream.write_all(b"\r\n")?;

        match meta.body {
            BodyKind::None => {}
            BodyKind::ContentLength(mut bytes_left) => {
                if !remaining.is_empty() {
                    let take = remaining.len().min(bytes_left);
                    upstream.write_all(&remaining[..take])?;
                    remaining.drain(..take);
                    bytes_left -= take;
                }
                copy_exact_bytes(client, upstream, bytes_left)?;
            }
            BodyKind::Chunked => {
                forward_chunked_body(client, upstream, &mut remaining)?;
            }
        }

        if !remaining.is_empty() {
            buffer.extend_from_slice(&remaining);
        }

        if meta.method.eq_ignore_ascii_case("CONNECT") {
            if !buffer.is_empty() {
                upstream.write_all(&buffer)?;
                buffer.clear();
            }
            io::copy(client, upstream)?;
            return Ok(());
        }
    }
}

#[cfg(any(unix, test))]
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

#[cfg(any(unix, test))]
fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(unix)]
fn read_until_header_block(
    client: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<usize>> {
    if let Some(pos) = find_header_terminator(buffer) {
        return Ok(Some(pos));
    }
    let mut chunk = [0_u8; 4096];
    loop {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-request headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_header_terminator(buffer) {
            return Ok(Some(pos));
        }
        if buffer.len() > 1024 * 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed 128KiB",
            ));
        }
    }
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestMetadata {
    method: String,
    body: BodyKind,
}

#[cfg(any(unix, test))]
fn parse_request_metadata(header_block: &[u8]) -> io::Result<RequestMetadata> {
    let head_str = std::str::from_utf8(header_block).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "request headers are not valid utf-8",
        )
    })?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();

    let mut transfer_chunked = false;
    let mut content_length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name_lc = name.trim().to_ascii_lowercase();
            let value_trim = value.trim();
            if name_lc == "transfer-encoding" && value_trim.to_ascii_lowercase().contains("chunked")
            {
                transfer_chunked = true;
            } else if name_lc == "content-length" {
                content_length = value_trim.parse::<usize>().ok();
            }
        }
    }

    let body = if transfer_chunked {
        BodyKind::Chunked
    } else if let Some(n) = content_length {
        if n == 0 {
            BodyKind::None
        } else {
            BodyKind::ContentLength(n)
        }
    } else {
        BodyKind::None
    };

    Ok(RequestMetadata { method, body })
}

#[cfg(unix)]
fn copy_exact_bytes(
    client: &mut TcpStream,
    upstream: &mut UnixStream,
    mut left: usize,
) -> io::Result<()> {
    let mut chunk = [0_u8; 8192];
    while left > 0 {
        let to_read = chunk.len().min(left);
        let read = client.read(&mut chunk[..to_read])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed mid-request body",
            ));
        }
        upstream.write_all(&chunk[..read])?;
        left -= read;
    }
    Ok(())
}

#[cfg(unix)]
fn forward_chunked_body(
    client: &mut TcpStream,
    upstream: &mut UnixStream,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    loop {
        let line_end = read_until_crlf(client, buffer)?;
        let line = &buffer[..line_end];
        let size_hex = std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.split(';').next())
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size line"))?;
        upstream.write_all(&buffer[..line_end + 2])?;
        buffer.drain(..line_end + 2);

        let needed = chunk_size + 2;
        ensure_buffered(client, buffer, needed)?;
        upstream.write_all(&buffer[..needed])?;
        buffer.drain(..needed);

        if chunk_size == 0 {
            // Forward trailing headers until CRLF CRLF.
            loop {
                let tail_end = read_until_crlf(client, buffer)?;
                upstream.write_all(&buffer[..tail_end + 2])?;
                let is_blank = tail_end == 0;
                buffer.drain(..tail_end + 2);
                if is_blank {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(unix)]
fn ensure_buffered(client: &mut TcpStream, buffer: &mut Vec<u8>, needed: usize) -> io::Result<()> {
    let mut chunk = [0_u8; 4096];
    while buffer.len() < needed {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while buffering body",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

#[cfg(unix)]
fn read_until_crlf(client: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<usize> {
    if let Some(pos) = find_crlf(buffer) {
        return Ok(pos);
    }
    let mut chunk = [0_u8; 1024];
    loop {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while reading chunk line",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_crlf(buffer) {
            return Ok(pos);
        }
    }
}

#[cfg(unix)]
fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{BodyKind, append_missing_headers, find_header_terminator, parse_request_metadata};

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

    #[test]
    fn header_block_ends_with_single_crlf_for_terminator() {
        // `append_missing_headers` rebuilds the header block and always
        // ends with `\r\n`. The caller then writes exactly one more `\r\n`
        // to complete the blank-line terminator (`\r\n\r\n` total). Verify
        // that the rebuilt block ends with `\r\n` so that one extra `\r\n`
        // produces exactly the correct HTTP blank-line separator — not a
        // spurious extra blank line that would corrupt CONNECT tunnels.
        let mut req_head = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n".to_vec();
        let mut headers = BTreeMap::new();
        headers.insert("x-firma-session-id".to_string(), "sess_001".to_string());
        append_missing_headers(&mut req_head, &headers).expect("append headers");
        assert!(
            req_head.ends_with(b"\r\n"),
            "header block must end with \\r\\n so caller can append one more \\r\\n"
        );
        assert!(
            !req_head.ends_with(b"\r\n\r\n"),
            "header block must NOT already contain the blank-line terminator"
        );
    }

    #[test]
    fn parses_content_length_body_metadata() {
        let req = b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\n";
        let meta = parse_request_metadata(req).expect("metadata");
        assert_eq!(meta.method, "POST");
        assert_eq!(meta.body, BodyKind::ContentLength(12));
    }

    #[test]
    fn parses_chunked_body_metadata() {
        let req = b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let meta = parse_request_metadata(req).expect("metadata");
        assert_eq!(meta.body, BodyKind::Chunked);
    }
}
