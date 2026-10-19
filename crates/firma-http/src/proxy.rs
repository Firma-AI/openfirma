use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

const MAX_HEADER_BYTES: usize = 128 * 1024;

/// Forwards HTTP/1 requests while replacing caller-supplied attribution headers.
///
/// `on_request` receives the parsed method and request target before each request is
/// forwarded. The target may contain sensitive query or fragment data; callers are
/// responsible for sanitizing it before logging.
///
/// # Errors
///
/// Returns an I/O error when reading or writing fails, or [`io::ErrorKind::InvalidData`]
/// when a header block is not UTF-8, exceeds the size limit, or has invalid chunk framing.
pub fn forward_http1_requests<R, W, F>(
    client: &mut R,
    upstream: &mut W,
    attribution_headers: &BTreeMap<String, String>,
    mut on_request: F,
) -> io::Result<()>
where
    R: Read,
    W: Write,
    F: FnMut(&str, &str),
{
    let mut buffer = Vec::new();
    loop {
        let Some(header_end) = read_until_header_block(client, &mut buffer)? else {
            return Ok(());
        };

        let mut request = std::mem::take(&mut buffer);
        let mut remaining = request.split_off(header_end + 4);
        request.truncate(header_end);

        let meta = parse_request_metadata(&request)?;
        on_request(&meta.method, &meta.target);
        replace_attribution_headers(&mut request, attribution_headers)?;

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
            BodyKind::Chunked => forward_chunked_body(client, upstream, &mut remaining)?,
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

fn replace_attribution_headers(
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
    let authoritative_names = attribution_headers
        .keys()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();

    let mut rebuilt = String::new();
    rebuilt.push_str(request_line);
    rebuilt.push_str("\r\n");
    for line in head_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        if line.split_once(':').is_some_and(|(name, _)| {
            authoritative_names.contains(&name.trim().to_ascii_lowercase())
        }) {
            continue;
        }
        rebuilt.push_str(line);
        rebuilt.push_str("\r\n");
    }
    for (name, value) in attribution_headers {
        rebuilt.push_str(name);
        rebuilt.push_str(": ");
        rebuilt.push_str(value);
        rebuilt.push_str("\r\n");
    }
    *header_block = rebuilt.into_bytes();
    Ok(())
}

fn read_until_header_block<R: Read>(
    client: &mut R,
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
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers exceed 128KiB",
            ));
        }
    }
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
}

struct RequestMetadata {
    method: String,
    target: String,
    body: BodyKind,
}

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
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts.next().unwrap_or_default().to_string();
    let target = request_line_parts.next().unwrap_or_default().to_string();

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
    } else if let Some(length) = content_length {
        if length == 0 {
            BodyKind::None
        } else {
            BodyKind::ContentLength(length)
        }
    } else {
        BodyKind::None
    };
    Ok(RequestMetadata {
        method,
        target,
        body,
    })
}

fn copy_exact_bytes<R: Read, W: Write>(
    client: &mut R,
    upstream: &mut W,
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

fn forward_chunked_body<R: Read, W: Write>(
    client: &mut R,
    upstream: &mut W,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    loop {
        let line_end = read_until_crlf(client, buffer)?;
        let line = &buffer[..line_end];
        let size_hex = std::str::from_utf8(line)
            .ok()
            .and_then(|line| line.split(';').next())
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size line"))?;
        upstream.write_all(&buffer[..line_end + 2])?;
        buffer.drain(..line_end + 2);

        if chunk_size == 0 {
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

        let needed = chunk_size.checked_add(2).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk size exceeds framing limit",
            )
        })?;
        ensure_buffered(client, buffer, needed)?;
        upstream.write_all(&buffer[..needed])?;
        buffer.drain(..needed);
    }
}

fn ensure_buffered<R: Read>(client: &mut R, buffer: &mut Vec<u8>, needed: usize) -> io::Result<()> {
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

fn read_until_crlf<R: Read>(client: &mut R, buffer: &mut Vec<u8>) -> io::Result<usize> {
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

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}
