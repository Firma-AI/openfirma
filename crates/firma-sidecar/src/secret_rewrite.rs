//! Content-Type-driven rewriter for the secret redact path.
//!
//! Two operations:
//!
//! - **Rehydrate** (outbound): replace `firma-secret://` placeholder tokens in
//!   a request body with the real secret bytes, encoded to fit the surrounding
//!   content type.
//! - **Mask** (inbound): replace occurrences of known secret values in a
//!   response body with their placeholder tokens.
//!
//! Both operations work on a flat byte buffer. The caller is responsible for
//! chunking, streaming overlap buffers, and supplying the match positions (from
//! a `SecretStore`-style scanner). This module only handles the rewrite math
//! and encoding.

/// How to encode the secret value before substituting it into the body.
///
/// The codec is selected per-request from the `Content-Type` header; when the
/// header is absent or inconclusive, [`ContentType::sniff`] probes the first
/// non-whitespace bytes of the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// `application/json` or any `application/*+json`.
    Json,
    /// `application/x-www-form-urlencoded`.
    FormEncoded,
    /// `application/xml`, `text/xml`, or any `application/*+xml`.
    Xml,
    /// `text/plain` or any explicitly textual type.
    Text,
    /// `application/octet-stream`, unknown, or absent — no encoding applied.
    Raw,
}

impl ContentType {
    /// Determine the content type from a `Content-Type` header value.
    ///
    /// Only the media type prefix (before any `;` parameters) is considered.
    /// Returns `None` when the header is absent or clearly `application/octet-stream`,
    /// triggering body-sniffing fallback in the caller.
    #[must_use]
    pub fn from_header(header: Option<&str>) -> Option<Self> {
        let header = header?;
        let media_type = header.split(';').next().unwrap_or(header).trim();
        let ct = media_type.to_ascii_lowercase();
        if ct == "application/json" || ct.ends_with("+json") {
            Some(Self::Json)
        } else if ct == "application/x-www-form-urlencoded" {
            Some(Self::FormEncoded)
        } else if ct == "application/xml"
            || ct == "text/xml"
            || ct.starts_with("application/") && (ct.ends_with("+xml") || ct.ends_with("/xml"))
        {
            Some(Self::Xml)
        } else if ct.starts_with("text/") {
            Some(Self::Text)
        } else if ct == "application/octet-stream" {
            None // trigger sniffing
        } else {
            Some(Self::Raw)
        }
    }

    /// Probe the first non-whitespace bytes of `body` to infer content type.
    #[must_use]
    pub fn sniff(body: &[u8]) -> Self {
        let first = body.iter().find(|&&b| !b.is_ascii_whitespace()).copied();
        match first {
            Some(b'{' | b'[') => Self::Json,
            Some(b'<') => Self::Xml,
            _ => {
                // Form-encoded: contains `=` without leading `{` or `<`.
                if body.contains(&b'=') {
                    Self::FormEncoded
                } else {
                    Self::Raw
                }
            }
        }
    }

    /// Resolve content type: use `header` when available and unambiguous,
    /// otherwise sniff `body`.
    #[must_use]
    pub fn resolve(header: Option<&str>, body: &[u8]) -> Self {
        Self::from_header(header).unwrap_or_else(|| Self::sniff(body))
    }
}

/// One outbound rehydration operation: replace `body[start..end]` (a
/// placeholder token) with `secret` encoded for the body's content type.
#[derive(Debug)]
pub struct RehydrateOp<'a> {
    /// Inclusive start byte offset of the placeholder in the body.
    pub start: usize,
    /// Exclusive end byte offset of the placeholder in the body.
    pub end: usize,
    /// Raw secret bytes to substitute.
    pub secret: &'a [u8],
}

/// One inbound masking operation: replace `body[start..end]` (a raw secret
/// value) with `placeholder`.
#[derive(Debug)]
pub struct MaskOp<'a> {
    /// Inclusive start byte offset of the secret value in the body.
    pub start: usize,
    /// Exclusive end byte offset of the secret value in the body.
    pub end: usize,
    /// Placeholder token to substitute in place of the secret.
    pub placeholder: &'a str,
}

/// Apply outbound rehydration to `body`.
///
/// Replaces each `firma-secret://` placeholder at the positions given by `ops`
/// with the corresponding secret value encoded for `content_type`. Ops must be
/// sorted by `start` and non-overlapping (as produced by an Aho-Corasick
/// leftmost-longest scan).
///
/// # Panics
///
/// Panics in debug builds if `ops` are not sorted or contain out-of-range
/// offsets. In release builds the output is unspecified but not unsound.
#[must_use]
pub fn rehydrate_body(body: &[u8], content_type: ContentType, ops: &[RehydrateOp<'_>]) -> Vec<u8> {
    apply_ops(body, ops, encode_secret, content_type)
}

/// Apply inbound masking to `body`.
///
/// Replaces each occurrence of a raw secret value at the positions given by
/// `ops` with the corresponding placeholder token (raw bytes, no encoding).
/// Ops must be sorted by `start` and non-overlapping.
#[must_use]
pub fn mask_body(body: &[u8], ops: &[MaskOp<'_>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for op in ops {
        debug_assert!(op.start >= cursor);
        debug_assert!(op.end <= body.len());
        out.extend_from_slice(&body[cursor..op.start]);
        out.extend_from_slice(op.placeholder.as_bytes());
        cursor = op.end;
    }
    out.extend_from_slice(&body[cursor..]);
    out
}

/// Generic apply: iterate ops, copying unchanged segments and substituting
/// encoded replacements. `encode` receives `(bytes, content_type)`.
fn apply_ops<E>(body: &[u8], ops: &[RehydrateOp<'_>], encode: E, ct: ContentType) -> Vec<u8>
where
    E: Fn(&[u8], ContentType) -> Vec<u8>,
{
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for op in ops {
        debug_assert!(op.start >= cursor);
        debug_assert!(op.end <= body.len());
        out.extend_from_slice(&body[cursor..op.start]);
        out.extend_from_slice(&encode(op.secret, ct));
        cursor = op.end;
    }
    out.extend_from_slice(&body[cursor..]);
    out
}

/// Encode `secret` bytes so they are safe to embed in a body of `content_type`.
fn encode_secret(secret: &[u8], content_type: ContentType) -> Vec<u8> {
    match content_type {
        ContentType::Json => json_escape(secret),
        ContentType::FormEncoded => form_encode(secret),
        ContentType::Xml => xml_escape(secret),
        ContentType::Text | ContentType::Raw => secret.to_vec(),
    }
}

/// JSON string escaping (RFC 8259 §7).
///
/// Escapes `"`, `\`, and control characters (U+0000–U+001F). Multi-byte UTF-8
/// sequences pass through unmodified; non-UTF-8 bytes are represented as
/// `\uXXXX` (two surrogate halves if needed) to ensure the output is valid.
fn json_escape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 4);
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        match b {
            b'"' => {
                out.extend_from_slice(b"\\\"");
                i += 1;
            }
            b'\\' => {
                out.extend_from_slice(b"\\\\");
                i += 1;
            }
            b'\n' => {
                out.extend_from_slice(b"\\n");
                i += 1;
            }
            b'\r' => {
                out.extend_from_slice(b"\\r");
                i += 1;
            }
            b'\t' => {
                out.extend_from_slice(b"\\t");
                i += 1;
            }
            0x00..=0x1F => {
                // Generic control character: \uXXXX
                let _ = write_unicode_escape(&mut out, u32::from(b));
                i += 1;
            }
            0x80..=0xFF => {
                // Non-ASCII: attempt to decode as UTF-8 and pass through; for
                // truncated or invalid sequences fall back to \uXXXX.
                let rest = &input[i..];
                let decoded = std::str::from_utf8(rest)
                    .ok()
                    .or_else(|| std::str::from_utf8(&rest[..rest.len().min(4)]).ok())
                    .and_then(|s| s.chars().next());
                if let Some(ch) = decoded {
                    out.extend_from_slice(ch.to_string().as_bytes());
                    i += ch.len_utf8();
                } else {
                    let _ = write_unicode_escape(&mut out, u32::from(b));
                    i += 1;
                }
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn write_unicode_escape(out: &mut Vec<u8>, codepoint: u32) -> std::fmt::Result {
    use std::fmt::Write;
    let mut buf = String::new();
    write!(buf, "\\u{codepoint:04X}")?;
    out.extend_from_slice(buf.as_bytes());
    Ok(())
}

/// Percent-encode `input` for `application/x-www-form-urlencoded`.
///
/// Leaves RFC 3986 unreserved characters (`[A-Za-z0-9-._~]`) unencoded;
/// every other byte becomes `%XX`.
fn form_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0F));
        }
    }
    out
}

/// XML character escaping for element content and attribute values.
fn xml_escape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 8);
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            _ => out.push(b),
        }
    }
    out
}

fn hex_upper(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ContentType detection ────────────────────────────────────────────────

    #[test]
    fn content_type_from_json_header() {
        assert_eq!(
            ContentType::from_header(Some("application/json")),
            Some(ContentType::Json)
        );
        assert_eq!(
            ContentType::from_header(Some("application/json; charset=utf-8")),
            Some(ContentType::Json)
        );
    }

    #[test]
    fn content_type_from_form_header() {
        assert_eq!(
            ContentType::from_header(Some("application/x-www-form-urlencoded")),
            Some(ContentType::FormEncoded)
        );
    }

    #[test]
    fn content_type_from_xml_headers() {
        for hdr in ["application/xml", "text/xml", "application/atom+xml"] {
            assert_eq!(
                ContentType::from_header(Some(hdr)),
                Some(ContentType::Xml),
                "unexpected for {hdr}"
            );
        }
    }

    #[test]
    fn content_type_octet_stream_triggers_sniffing() {
        assert_eq!(
            ContentType::from_header(Some("application/octet-stream")),
            None
        );
    }

    #[test]
    fn content_type_absent_triggers_sniffing() {
        assert_eq!(ContentType::from_header(None), None);
    }

    #[test]
    fn sniff_json_object() {
        assert_eq!(ContentType::sniff(b"{\"key\":\"val\"}"), ContentType::Json);
    }

    #[test]
    fn sniff_json_array() {
        assert_eq!(ContentType::sniff(b"[1,2,3]"), ContentType::Json);
    }

    #[test]
    fn sniff_xml() {
        assert_eq!(ContentType::sniff(b"<root/>"), ContentType::Xml);
    }

    #[test]
    fn sniff_form_encoded() {
        assert_eq!(
            ContentType::sniff(b"key=value&other=x"),
            ContentType::FormEncoded
        );
    }

    #[test]
    fn sniff_raw_fallback() {
        assert_eq!(ContentType::sniff(b"some binary\x00data"), ContentType::Raw);
    }

    #[test]
    fn resolve_prefers_header_over_body_sniffing() {
        // The body looks like XML, but a conclusive header always wins.
        assert_eq!(
            ContentType::resolve(Some("application/json"), b"<root/>"),
            ContentType::Json
        );
    }

    #[test]
    fn resolve_falls_back_to_sniffing_when_header_is_absent_or_inconclusive() {
        assert_eq!(ContentType::resolve(None, b"<root/>"), ContentType::Xml);
        assert_eq!(
            ContentType::resolve(Some("application/octet-stream"), b"<root/>"),
            ContentType::Xml
        );
    }

    // ── rehydrate_body ───────────────────────────────────────────────────────

    fn rehydrate(body: &[u8], ct: ContentType, ops: &[(&str, &[u8])]) -> Vec<u8> {
        // Build ops from (placeholder_bytes_range, secret) tuples; find each
        // placeholder in the body.
        let ops: Vec<RehydrateOp<'_>> = ops
            .iter()
            .filter_map(|(placeholder, secret)| {
                let ph = placeholder.as_bytes();
                body.windows(ph.len()).enumerate().find_map(|(i, w)| {
                    if w == ph {
                        Some(RehydrateOp {
                            start: i,
                            end: i + ph.len(),
                            secret,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();
        let mut sorted = ops;
        sorted.sort_by_key(|op| op.start);
        rehydrate_body(body, ct, &sorted)
    }

    #[test]
    fn rehydrate_json_body_escapes_quotes() {
        let body = b"{\"token\":\"firma-secret://bw/tk\"}";
        let secret = b"s\"ec\"ret";
        let ops = [("firma-secret://bw/tk", secret.as_slice())];
        let result = rehydrate(body, ContentType::Json, &ops);
        let result_str = std::str::from_utf8(&result).expect("utf8");
        assert!(result_str.contains("s\\\"ec\\\"ret"), "got: {result_str}");
    }

    #[test]
    fn rehydrate_json_body_escapes_backslash() {
        let body = b"{\"p\":\"firma-secret://bw/k\"}";
        let ops = [("firma-secret://bw/k", b"a\\b".as_slice())];
        let result = rehydrate(body, ContentType::Json, &ops);
        let s = std::str::from_utf8(&result).expect("utf8");
        assert!(s.contains("a\\\\b"), "got: {s}");
    }

    #[test]
    fn rehydrate_form_body_percent_encodes() {
        let body = b"token=firma-secret://bw/k&other=x";
        let ops = [("firma-secret://bw/k", b"p@ss w0rd".as_slice())];
        let result = rehydrate(body, ContentType::FormEncoded, &ops);
        let s = std::str::from_utf8(&result).expect("utf8");
        assert_eq!(s, "token=p%40ss%20w0rd&other=x");
    }

    #[test]
    fn rehydrate_xml_body_escapes_entities() {
        let body = b"<auth>firma-secret://bw/k</auth>";
        let ops = [("firma-secret://bw/k", b"<secret&>".as_slice())];
        let result = rehydrate(body, ContentType::Xml, &ops);
        let s = std::str::from_utf8(&result).expect("utf8");
        assert_eq!(s, "<auth>&lt;secret&amp;&gt;</auth>");
    }

    #[test]
    fn rehydrate_raw_body_passes_through_unchanged() {
        let body = b"firma-secret://bw/k\x00data";
        let ops = [("firma-secret://bw/k", b"\x01\x02\x03".as_slice())];
        let result = rehydrate(body, ContentType::Raw, &ops);
        assert_eq!(result, b"\x01\x02\x03\x00data");
    }

    #[test]
    fn rehydrate_no_ops_returns_body_unchanged() {
        let body = b"no placeholders here";
        assert_eq!(rehydrate_body(body, ContentType::Json, &[]), body);
    }

    // ── mask_body ────────────────────────────────────────────────────────────

    #[test]
    fn mask_replaces_secret_with_placeholder() {
        let body = b"token: s3cr3t, other: stuff";
        let ops = [MaskOp {
            start: 7,
            end: 13,
            placeholder: "firma-secret://bw/token",
        }];
        let result = mask_body(body, &ops);
        assert_eq!(result, b"token: firma-secret://bw/token, other: stuff");
    }

    #[test]
    fn mask_multiple_occurrences() {
        let body = b"s3cr3t and s3cr3t again";
        let ops = [
            MaskOp {
                start: 0,
                end: 6,
                placeholder: "firma-secret://bw/x",
            },
            MaskOp {
                start: 11,
                end: 17,
                placeholder: "firma-secret://bw/x",
            },
        ];
        let result = mask_body(body, &ops);
        assert_eq!(result, b"firma-secret://bw/x and firma-secret://bw/x again");
    }

    #[test]
    fn mask_no_ops_returns_body_unchanged() {
        let body = b"no secrets here";
        assert_eq!(mask_body(body, &[]), body.as_slice());
    }

    // ── encoding edge cases ──────────────────────────────────────────────────

    #[test]
    fn json_escape_control_chars() {
        let result = json_escape(b"\x00\x01\x1F");
        assert_eq!(result, b"\\u0000\\u0001\\u001F");
    }

    #[test]
    fn json_escape_tab_newline_return() {
        assert_eq!(json_escape(b"\t\n\r"), b"\\t\\n\\r");
    }

    #[test]
    fn json_escape_passes_through_valid_multibyte_utf8() {
        let input = "€ café".as_bytes();
        assert_eq!(json_escape(input), input);
    }

    #[test]
    fn json_escape_invalid_utf8_falls_back_to_unicode_escape() {
        // 0xFF is never a valid UTF-8 lead byte, so the byte is escaped on
        // its own and the following ASCII byte is processed normally.
        assert_eq!(json_escape(&[0xFF, b'a']), b"\\u00FFa");
    }

    #[test]
    fn form_encode_unreserved_unchanged() {
        let input = b"abcABC123-._~";
        assert_eq!(form_encode(input), input.to_vec());
    }

    #[test]
    fn form_encode_special_bytes() {
        assert_eq!(form_encode(b"a b+c"), b"a%20b%2Bc");
    }

    #[test]
    fn xml_escape_all_entities() {
        assert_eq!(xml_escape(b"<a>&\"</a>"), b"&lt;a&gt;&amp;&quot;&lt;/a&gt;");
    }
}
