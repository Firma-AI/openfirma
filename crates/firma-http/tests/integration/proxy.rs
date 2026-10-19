use std::collections::BTreeMap;
use std::io::{self, Cursor};

use firma_http::forward_http1_requests;

type ForwardedRequest = (String, String);
type ForwardResult = (Vec<u8>, Vec<ForwardedRequest>);

fn forward(input: &[u8], headers: &BTreeMap<String, String>) -> io::Result<ForwardResult> {
    let mut input = Cursor::new(input);
    let mut output = Vec::new();
    let mut requests = Vec::new();
    forward_http1_requests(&mut input, &mut output, headers, |method, target| {
        requests.push((method.to_string(), target.to_string()));
    })?;
    Ok((output, requests))
}

#[test]
fn replaces_attribution_headers_case_insensitively() {
    let input = b"GET http://example.com/ HTTP/1.1\r\nX-Firma-Agent: spoofed\r\nX-Unrelated: retained\r\n\r\n";
    let headers = BTreeMap::from([("x-firma-agent".to_string(), "guest".to_string())]);
    let (output, requests) = forward(input, &headers).expect("forward request");

    assert_eq!(
        requests,
        [("GET".to_string(), "http://example.com/".to_string())]
    );
    assert_eq!(output, b"GET http://example.com/ HTTP/1.1\r\nX-Unrelated: retained\r\nx-firma-agent: guest\r\n\r\n");
}

#[test]
fn forwards_content_length_and_pipelined_requests() {
    let input = b"POST /one HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /two HTTP/1.1\r\n\r\n";
    let (output, requests) = forward(input, &BTreeMap::new()).expect("forward requests");
    assert_eq!(output, input);
    assert_eq!(requests.len(), 2);
}

#[test]
fn forwards_chunked_body_with_trailers() {
    let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\nX-Trailer: yes\r\n\r\n";
    let (output, _) = forward(input, &BTreeMap::new()).expect("forward request");
    assert_eq!(output, input);
}

#[test]
fn forwards_zero_chunk_without_trailers_and_next_request() {
    let input = b"POST /one HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /two HTTP/1.1\r\n\r\n";
    let (output, requests) = forward(input, &BTreeMap::new()).expect("forward requests");

    assert_eq!(output, input);
    assert_eq!(
        requests,
        [
            ("POST".into(), "/one".into()),
            ("GET".into(), "/two".into())
        ]
    );
}

#[test]
fn forwards_connect_bytes_without_an_extra_crlf() {
    let input = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\ntunnel-bytes";
    let (output, _) = forward(input, &BTreeMap::new()).expect("forward request");
    assert_eq!(output, input);
}

#[test]
fn rejects_non_utf8_headers() {
    let error = forward(b"GET / HTTP/1.1\r\nX-Test: \xff\r\n\r\n", &BTreeMap::new())
        .expect_err("non-UTF-8 headers must fail");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "request headers are not valid utf-8");
}

#[test]
fn rejects_headers_over_128_kib_without_a_terminator() {
    let input = vec![b'a'; 128 * 1024 + 1];
    let error = forward(&input, &BTreeMap::new()).expect_err("oversized headers must fail");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "request headers exceed 128KiB");
}

#[test]
fn rejects_lf_only_headers_as_incomplete() {
    let error = forward(b"GET / HTTP/1.1\nHost: example.com\n\n", &BTreeMap::new())
        .expect_err("LF-only headers must not parse");
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(error.to_string(), "connection closed mid-request headers");
}

#[test]
fn rejects_invalid_chunk_size_with_existing_classification() {
    let input = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n";
    let error = forward(input, &BTreeMap::new()).expect_err("invalid chunk size must fail");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "invalid chunk size line");
}

#[test]
fn rejects_chunk_sizes_that_overflow_body_framing() {
    for size in [usize::MAX - 1, usize::MAX] {
        let input = format!("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n");
        let error = forward(input.as_bytes(), &BTreeMap::new())
            .expect_err("body length plus CRLF cannot fit in usize");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
