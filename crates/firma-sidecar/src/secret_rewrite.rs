//! Content-Type-driven rewriter for the secret redact path.
//!
//! Two operations:
//!
//! - **Rehydrate** (outbound): replace placeholder tokens in a request body
//!   with the real secret bytes, encoded to fit the surrounding content type.
//! - **Mask** (inbound): replace occurrences of known secret values in a
//!   response body with their placeholder tokens.
//!
//! Both operations work on a flat byte buffer. The caller is responsible for
//! chunking, streaming overlap buffers, and supplying the match positions (from
//! a `SecretStore`-style scanner). This module only handles the rewrite math
//! and encoding.

use std::ops::Range;

use firma_secret_provider::{ExposeSecret, SecretPlaceholder, SecretString};
use json_escape::token::UnescapedToken;

#[derive(Debug, thiserror::Error)]
#[error("unrecognized content type")]
pub struct UnrecognizedContentType;

/// How to encode the secret value before substituting it into the body.
///
/// The codec is selected per-request from the `Content-Type` header; when the
/// header is absent, [`ContentType::sniff`] probes the first non-whitespace
/// bytes of the body instead. A header that is present but maps to neither a
/// known type nor `Raw`, or body bytes that sniffing can't classify, fail
/// with [`UnrecognizedContentType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// `application/json` or any `application/*+json`.
    Json,
    /// `application/x-www-form-urlencoded`.
    FormEncoded,
    /// `application/xml`, `text/xml`, or any `application/*+xml`.
    Xml,
    /// Any `text/*` or `application/octet-stream` — no encoding applied.
    Raw,
}

impl ContentType {
    /// Determine the content type from a `Content-Type` header value.
    ///
    /// Only the media type prefix (before any `;` parameters) is considered.
    /// Returns `Ok(None)` when the header is absent, triggering body-sniffing
    /// fallback in the caller. Returns `Err` for a header present but not
    /// recognized as JSON, form-encoded, XML, or raw.
    fn from_header(
        header: Option<headers::ContentType>,
    ) -> Result<Option<Self>, UnrecognizedContentType> {
        let Some(header) = header else {
            return Ok(None); // trigger sniffing
        };
        let mime = headers::Mime::from(header);
        match (mime.type_(), mime.subtype(), mime.suffix()) {
            (mime::APPLICATION, mime::JSON, _) | (_, _, Some(mime::JSON)) => Ok(Some(Self::Json)),
            (mime::APPLICATION, mime::WWW_FORM_URLENCODED, _) => Ok(Some(Self::FormEncoded)),
            (mime::APPLICATION | mime::TEXT, mime::XML, _)
            | (mime::APPLICATION, _, Some(mime::XML)) => Ok(Some(Self::Xml)),
            (mime::TEXT, _, _) | (mime::APPLICATION, mime::OCTET_STREAM, _) => Ok(Some(Self::Raw)),
            _ => Err(UnrecognizedContentType),
        }
    }

    /// Probe the first non-whitespace bytes of `body` to infer content type.
    ///
    /// Returns `Err` when the bytes look like neither JSON, XML, nor
    /// form-encoded data.
    fn sniff(body: &[u8]) -> Result<Self, UnrecognizedContentType> {
        let first = body.iter().find(|&&b| !b.is_ascii_whitespace()).copied();
        match first {
            Some(b'{' | b'[') => Ok(Self::Json),
            Some(b'<') => Ok(Self::Xml),
            _ => {
                // Form-encoded: contains `=` without leading `{` or `<`.
                if body.contains(&b'=') {
                    Ok(Self::FormEncoded)
                } else {
                    Err(UnrecognizedContentType)
                }
            }
        }
    }

    /// Resolve content type: use `header` when present, otherwise sniff
    /// `body`. Fails if the header is present but unrecognized, or if
    /// sniffing can't classify the body.
    pub(crate) fn resolve(
        header: Option<headers::ContentType>,
        body: &[u8],
    ) -> Result<Self, UnrecognizedContentType> {
        let Some(content_type) = Self::from_header(header)? else {
            return Self::sniff(body);
        };
        Ok(content_type)
    }
}

/// One outbound rehydration operation: replace `body[start..end]` (a
/// placeholder token) with `secret` encoded for the body's content type.
#[derive(Debug)]
pub(crate) struct RehydrateOp<'a> {
    /// Byte offset range of the placeholder in the body.
    pub(crate) range: Range<usize>,
    /// Secret string to substitute.
    pub(crate) secret: &'a SecretString,
}

/// One inbound masking operation: replace `body[start..end]` (a raw secret
/// value) with `placeholder`.
#[derive(Debug)]
pub(crate) struct MaskOp<'a> {
    /// Byte offset range of the secret value in the body.
    pub(crate) range: Range<usize>,
    /// Placeholder token to substitute in place of the secret.
    pub(crate) placeholder: &'a SecretPlaceholder,
}

/// Apply outbound rehydration to `body`.
///
/// Replaces each placeholder at the positions given by `ops` with the
/// corresponding secret value encoded for `content_type`. Ops must be
/// sorted by `start` and non-overlapping (as produced by an Aho-Corasick
/// leftmost-longest scan).
///
/// # Panics
///
/// Panics if `ops` are not sorted by `start` or contain out-of-range offsets:
/// slice range indexing on `body` enforces this unconditionally, in both
/// debug and release builds.
#[must_use]
pub(crate) fn rehydrate_body(
    body: &[u8],
    content_type: ContentType,
    ops: &[RehydrateOp],
) -> Vec<u8> {
    apply_ops(body, ops, encode_secret, content_type)
}

/// Apply inbound masking to `body`.
///
/// Replaces each occurrence of a raw secret value at the positions given by
/// `ops` with the corresponding placeholder token (raw bytes, no encoding).
/// Ops must be sorted by `start` and non-overlapping.
///
/// # Panics
///
/// Panics if `ops` are not sorted by `start` or contain out-of-range offsets:
/// slice range indexing on `body` enforces this unconditionally, in both
/// debug and release builds.
#[must_use]
pub(crate) fn mask_body(body: &[u8], ops: &[MaskOp<'_>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for op in ops {
        debug_assert!(op.range.start >= cursor);
        debug_assert!(op.range.end <= body.len());
        out.extend_from_slice(&body[cursor..op.range.start]);
        out.extend(op.placeholder.to_string().into_bytes());
        cursor = op.range.end;
    }
    out.extend_from_slice(&body[cursor..]);
    out
}

/// Generic apply: iterate ops, copying unchanged segments and substituting
/// encoded replacements. `encode` receives `(bytes, content_type)`.
fn apply_ops<E>(body: &[u8], ops: &[RehydrateOp], encode: E, ct: ContentType) -> Vec<u8>
where
    E: Fn(&SecretString, ContentType) -> String,
{
    let mut out = Vec::with_capacity(body.len());
    let mut cursor = 0;
    for op in ops {
        debug_assert!(op.range.start >= cursor);
        debug_assert!(op.range.end <= body.len());
        out.extend_from_slice(&body[cursor..op.range.start]);
        out.extend_from_slice(encode(op.secret, ct).as_bytes());
        cursor = op.range.end;
    }
    out.extend_from_slice(&body[cursor..]);
    out
}

/// Encode `secret` bytes so they are safe to embed in a body of `content_type`.
fn encode_secret(secret: &SecretString, content_type: ContentType) -> String {
    match content_type {
        ContentType::Json => json_escape(secret),
        ContentType::FormEncoded => form_encode(secret),
        ContentType::Xml => xml_escape(secret),
        ContentType::Raw => secret.expose_secret().to_owned(),
    }
}

/// Find the raw byte ranges in `body` that decode to `secret` under
/// `content_type`'s escaping rules — either the whole candidate value, or a
/// word-bounded substring of one (a secret embedded in longer text, including
/// when the secret's own bytes were escaped: `\"`, `&amp;`, `%XX`). Decoding
/// rather than enumerating encodings catches every equivalent spelling for
/// free (e.g. `%2b` vs `%2B`, `"` vs `\u0022`, a numeric XML character
/// reference vs the named entity, arbitrarily zero-padded).
///
/// Delegates decoding to the crates [`encode_secret`] uses for encoding
/// (`json_escape`/`serde_json`, `form_urlencoded`, `quick_xml`); this module
/// only locates candidate spans and maps decoded byte positions back to raw
/// bytes ([`DecodedContent`]).
pub(crate) fn find_decoded_secret_spans(
    body: &[u8],
    content_type: ContentType,
    secret: &SecretString,
) -> Vec<Range<usize>> {
    match content_type {
        ContentType::Json => find_json_string_spans(body, secret),
        ContentType::FormEncoded => find_form_value_spans(body, secret),
        ContentType::Xml => find_xml_text_spans(body, secret),
        ContentType::Raw => {
            let pattern = secret.expose_secret().as_bytes();
            if pattern.is_empty() {
                return vec![];
            }
            body.windows(pattern.len())
                .enumerate()
                .filter(|(_, window)| *window == pattern)
                .map(|(start, _)| start..start + pattern.len())
                .collect()
        }
    }
}

/// Decoded content and a byte-for-byte map back to the raw bytes it came
/// from.
///
/// The per-format decoders split their input into literal runs (which decode
/// to themselves, 1:1) and escape runs (`\"`, `&amp;`, `%XX`, `+`), recording
/// for each decoded byte the raw span of the bytes it was encoded in. That
/// lets a decoded byte range — e.g. a word-bounded secret found in the decoded
/// plaintext — be translated back to the exact raw bytes to redact, including
/// the full escape when the secret ends mid-escape.
struct DecodedContent {
    decoded: Vec<u8>,
    /// For each byte in [`Self::decoded`], the raw span of input bytes it was
    /// encoded in.
    raw: Vec<Range<usize>>,
}

impl DecodedContent {
    fn push(&mut self, byte: u8, raw: Range<usize>) {
        self.decoded.push(byte);
        self.raw.push(raw);
    }

    /// Word-bounded occurrences of `secret` in [`Self::decoded`], translated
    /// back to raw byte spans relative to the input the content was decoded
    /// from.
    fn find_word_bounded_raw_spans(&self, secret: &str) -> Vec<Range<usize>> {
        find_word_bounded_spans(&self.decoded, secret)
            .into_iter()
            .map(|span| self.raw[span.start].start..self.raw[span.end - 1].end)
            .collect()
    }
}

/// Decode the content of a JSON string literal (RFC 8259 §7) into
/// [`DecodedContent`].
///
/// Decoding is delegated to `json_escape`'s token iterator, which yields each
/// literal run as a borrowed slice and each escape sequence as its decoded
/// `char`. The raw length of an escape is recovered from that character: a
/// simple escape (`\n`) spans 2 bytes, a `\uXXXX` escape 6, and a surrogate
/// pair (`\uD83D\uDE00`) 12 — the character's UTF-8 width distinguishes the
/// pair from a single `\uXXXX`.
///
/// Returns `None` for an invalid escape sequence; the caller treats the
/// literal as unmatchable.
fn decode_json_content(content: &[u8]) -> Option<DecodedContent> {
    let mut out = DecodedContent {
        decoded: vec![],
        raw: vec![],
    };
    let mut raw_cursor = 0;
    for token in json_escape::token::unescape(content) {
        match token.ok()? {
            UnescapedToken::Literal(literal) => {
                for (k, &byte) in literal.iter().enumerate() {
                    out.push(byte, raw_cursor + k..raw_cursor + k + 1);
                }
                raw_cursor += literal.len();
            }
            UnescapedToken::Unescaped(ch) => {
                let escape_len = if ch.len_utf8() == 4 {
                    12
                } else if content.get(raw_cursor + 1) == Some(&b'u') {
                    6
                } else {
                    2
                };
                let mut buf = [0; 4];
                for &byte in ch.encode_utf8(&mut buf).as_bytes() {
                    out.push(byte, raw_cursor..raw_cursor + escape_len);
                }
                raw_cursor += escape_len;
            }
        }
    }
    Some(out)
}

/// Find a JSON string literal that contains `secret` as a word-bounded
/// substring of its decoded content, returned as raw byte spans.
///
/// Literals are decoded with `json_escape` ([`decode_json_content`]) so that a
/// secret whose own bytes were escaped — e.g. `"my \"quoted\" secret"` — is
/// still found, and the decoded byte span maps back to the raw bytes.
///
/// Literals with no escape sequences decode to their own raw bytes, so they
/// take the allocation-free raw scan directly.
fn find_json_string_spans(body: &[u8], secret: &SecretString) -> Vec<Range<usize>> {
    let secret = secret.expose_secret();
    let mut out = vec![];
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'"' {
            i += 1;
            continue;
        }
        let content_start = i;
        let mut j = content_start + 1;
        let mut has_escape = false;
        while j < body.len() && body[j] != b'"' {
            if body[j] == b'\\' {
                has_escape = true;
                j += if body.get(j + 1) == Some(&b'u') { 6 } else { 2 };
            } else {
                j += 1;
            }
        }
        let content_end = j.min(body.len());
        if body.get(content_end).is_some_and(|byte| *byte == b'"') {
            let content = &body[content_start + 1..content_end];
            let spans = if has_escape {
                decode_json_content(content)
                    .map(|decoded| decoded.find_word_bounded_raw_spans(secret))
                    .unwrap_or_default()
            } else {
                find_word_bounded_spans(content, secret)
            };
            out.extend(
                spans
                    .into_iter()
                    .map(|span| (content_start + 1 + span.start)..(content_start + 1 + span.end)),
            );
        }
        i = content_end + 1;
    }
    out
}

/// Find every non-overlapping, word-bounded occurrence of `needle` in
/// `haystack`.
///
/// A match is accepted only when the byte immediately before and after it
/// (if any) is not itself alphanumeric, `-`, or `_`. That rejects a `needle`
/// that is merely a coincidental prefix/suffix of a longer opaque token
/// (e.g. an unrelated id that happens to start with the same characters as
/// the secret), while still catching a secret embedded in ordinary text.
fn find_word_bounded_spans(haystack: &[u8], needle: &str) -> Vec<Range<usize>> {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return vec![];
    }
    let mut out = vec![];
    let mut pos = 0;
    while pos + needle.len() <= haystack.len() {
        if &haystack[pos..pos + needle.len()] == needle {
            let end = pos + needle.len();
            let left_ok = pos == 0 || !is_word_byte(haystack[pos - 1]);
            let right_ok = end == haystack.len() || !is_word_byte(haystack[end]);
            if left_ok && right_ok {
                out.push(pos..end);
                pos = end;
                continue;
            }
        }
        pos += 1;
    }
    out
}

/// Whether `b` is part of a "word" for [`find_word_bounded_spans`]'s
/// boundary check: alphanumeric or a common token-constituent separator
/// (`-`, `_`), the characters typically found inside credential-shaped
/// tokens.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Decode a form value into [`DecodedContent`] (`+` for a space, `%XX` for a
/// byte), tracking each byte's raw position. An invalid `%` sequence is
/// passed through literally, matching `form_urlencoded`.
fn decode_form_content(value: &[u8]) -> DecodedContent {
    let mut out = DecodedContent {
        decoded: vec![],
        raw: vec![],
    };
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'+' => {
                out.push(b' ', i..i + 1);
                i += 1;
            }
            b'%' => {
                if let (Some(hi), Some(lo)) =
                    (hex_digit(value.get(i + 1)), hex_digit(value.get(i + 2)))
                {
                    out.push(hi << 4 | lo, i..i + 3);
                    i += 3;
                } else {
                    out.push(b'%', i..i + 1);
                    i += 1;
                }
            }
            byte => {
                out.push(byte, i..i + 1);
                i += 1;
            }
        }
    }
    out
}

/// The value of `byte` as a hexadecimal digit, if it is one.
fn hex_digit(byte: Option<&u8>) -> Option<u8> {
    match byte {
        Some(b @ b'0'..=b'9') => Some(b - b'0'),
        Some(b @ b'a'..=b'f') => Some(b - b'a' + 10),
        Some(b @ b'A'..=b'F') => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Find a form field value (by byte span in `body`) that contains `secret`.
///
/// Values are decoded ([`decode_form_content`]) when they contain any escape
/// (`%` or `+`) so that a secret whose own bytes were percent-encoded — e.g.
/// `token=my%20secret%20here` for the secret `my secret here` — is still
/// found, with the decoded byte span mapped back to the raw bytes. Values
/// with no escapes decode to themselves and take the allocation-free raw
/// scan.
fn find_form_value_spans(body: &[u8], secret: &SecretString) -> Vec<Range<usize>> {
    let secret = secret.expose_secret();
    let mut out = vec![];
    let mut offset = 0;
    for pair in body.split(|&b| b == b'&') {
        let value_start = pair.iter().position(|&b| b == b'=').map_or(0, |p| p + 1);
        let value = &pair[value_start..];
        let spans = if value.contains(&b'%') || value.contains(&b'+') {
            decode_form_content(value).find_word_bounded_raw_spans(secret)
        } else {
            find_word_bounded_spans(value, secret)
        };
        out.extend(
            spans
                .into_iter()
                .map(|span| (offset + value_start + span.start)..(offset + value_start + span.end)),
        );
        offset += pair.len() + 1;
    }
    out
}

/// Decode XML entity references in a text node or attribute value into
/// [`DecodedContent`], tracking each byte's raw position.
///
/// Each `&...;` reference is unescaped with `quick_xml` (the decoder paired
/// with [`xml_escape`]); a reference that doesn't decode — e.g. an unknown
/// named entity — is left as a literal `&`, keeping the bytes aligned with
/// the input.
fn decode_xml_content(raw: &[u8]) -> DecodedContent {
    let mut out = DecodedContent {
        decoded: vec![],
        raw: vec![],
    };
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'&' {
            let Some(rel_end) = raw[i + 1..].iter().position(|&b| b == b';') else {
                out.push(b'&', i..i + 1);
                i += 1;
                continue;
            };
            let entity_end = i + 1 + rel_end;
            let decoded = std::str::from_utf8(&raw[i..=entity_end])
                .ok()
                .and_then(|entity| quick_xml::escape::unescape(entity).ok());
            if let Some(decoded) = decoded
                && decoded.chars().count() == 1
            {
                let bytes = decoded.as_bytes();
                for &byte in bytes {
                    out.push(byte, i..entity_end + 1);
                }
                i = entity_end + 1;
            } else {
                out.push(b'&', i..i + 1);
                i += 1;
            }
        } else {
            out.push(raw[i], i..i + 1);
            i += 1;
        }
    }
    out
}

/// Find an XML text node or attribute value (by byte span in `body`) that
/// contains `secret`, returned as raw byte spans.
///
/// Spans containing an entity reference are decoded ([`decode_xml_content`])
/// so that a secret whose own bytes were entity-escaped — e.g. `a&amp;b` for
/// the secret `a&b` — is still found, with the decoded byte span mapped back
/// to the raw bytes. Spans with no `&` decode to themselves and take the
/// allocation-free raw scan.
fn find_xml_text_spans(body: &[u8], secret: &SecretString) -> Vec<Range<usize>> {
    let secret_bytes = secret.expose_secret();
    let mut out = vec![];
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'<' {
            let Some(tag_end) = body[i..].iter().position(|&b| b == b'>') else {
                break;
            };
            let tag_end = i + tag_end;
            out.extend(find_xml_attribute_spans(&body[i..=tag_end], secret, i));
            i = tag_end + 1;
            continue;
        }
        let text_end = body[i..]
            .iter()
            .position(|&b| b == b'<')
            .map_or(body.len(), |p| i + p);
        let text_span = i..text_end;
        let text = &body[text_span.clone()];
        let spans = if text.contains(&b'&') {
            decode_xml_content(text).find_word_bounded_raw_spans(secret_bytes)
        } else {
            find_word_bounded_spans(text, secret_bytes)
        };
        out.extend(
            spans
                .into_iter()
                .map(|span| (text_span.start + span.start)..(text_span.start + span.end)),
        );
        i = text_end;
    }
    out
}

/// Find a quoted attribute value (by byte span within `tag`, a single
/// `<...>` element's bytes) that contains `secret`, returned as raw byte
/// spans. Entity references are handled as in [`find_xml_text_spans`].
fn find_xml_attribute_spans(tag: &[u8], secret: &SecretString, offset: usize) -> Vec<Range<usize>> {
    let secret = secret.expose_secret();
    let mut out = vec![];
    let mut i = 0;
    while i < tag.len() {
        let quote = tag[i];
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }
        let content_start = i + 1;
        let Some(rel_end) = tag[content_start..].iter().position(|&b| b == quote) else {
            break;
        };
        let content_end = content_start + rel_end;
        let content_span = content_start..content_end;
        let content = &tag[content_span.clone()];
        let spans = if content.contains(&b'&') {
            decode_xml_content(content).find_word_bounded_raw_spans(secret)
        } else {
            find_word_bounded_spans(content, secret)
        };
        out.extend(spans.into_iter().map(|span| {
            (offset + content_start + span.start)..(offset + content_start + span.end)
        }));
        i = content_end + 1;
    }
    out
}

/// JSON string escaping (RFC 8259 §7), delegated to `serde_json`.
///
/// `input` is decoded as UTF-8 lossily (invalid sequences become U+FFFD)
/// before escaping, since JSON strings are inherently Unicode text.
fn json_escape(input: &SecretString) -> String {
    let text = input.expose_secret();
    let quoted = serde_json::to_string(text).unwrap_or_default();
    let escaped = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_default();
    escaped.to_owned()
}

/// Percent-encode `input` for `application/x-www-form-urlencoded`, delegated
/// to the `form_urlencoded` crate (space becomes `+`; every other byte outside
/// the unreserved set becomes `%XX`).
fn form_encode(input: &SecretString) -> String {
    form_urlencoded::byte_serialize(input.expose_secret().as_bytes()).collect::<String>()
}

/// XML character escaping for element content and attribute values,
/// delegated to `quick_xml::escape::escape`.
///
/// `input` is decoded as UTF-8 lossily (invalid sequences become U+FFFD)
/// before escaping, since XML text content is inherently Unicode text.
fn xml_escape(input: &SecretString) -> String {
    let text = input.expose_secret();
    quick_xml::escape::escape(text).into_owned()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // ── ContentType detection ────────────────────────────────────────────────

    #[test]
    fn content_type_from_json_header() {
        assert_eq!(
            ContentType::from_header(Some(
                headers::ContentType::from_str("application/json").expect("valid content type")
            ))
            .expect("valid content type"),
            Some(ContentType::Json)
        );
        assert_eq!(
            ContentType::from_header(Some(
                headers::ContentType::from_str("application/json; charset=utf-8")
                    .expect("valid content type")
            ))
            .expect("valid content type"),
            Some(ContentType::Json)
        );
    }

    #[test]
    fn content_type_from_form_header() {
        assert_eq!(
            ContentType::from_header(Some(
                headers::ContentType::from_str("application/x-www-form-urlencoded")
                    .expect("valid content type")
            ))
            .expect("valid content type"),
            Some(ContentType::FormEncoded)
        );
    }

    #[test]
    fn content_type_from_xml_headers() {
        for hdr in ["application/xml", "text/xml", "application/atom+xml"] {
            assert_eq!(
                ContentType::from_header(Some(
                    headers::ContentType::from_str(hdr).expect("valid content type")
                ))
                .expect("valid content type"),
                Some(ContentType::Xml),
                "unexpected for {hdr}"
            );
        }
    }

    #[test]
    fn content_type_octet_stream_is_raw() {
        assert_eq!(
            ContentType::from_header(Some(
                headers::ContentType::from_str("application/octet-stream")
                    .expect("valid content type")
            ))
            .expect("valid content type"),
            Some(ContentType::Raw)
        );
    }

    #[test]
    fn content_type_absent_triggers_sniffing() {
        assert_eq!(
            ContentType::from_header(None).expect("valid content type"),
            None
        );
    }

    #[test]
    fn sniff_json_object() {
        assert_eq!(
            ContentType::sniff(b"{\"key\":\"val\"}").expect("valid content type"),
            ContentType::Json
        );
    }

    #[test]
    fn sniff_json_array() {
        assert_eq!(
            ContentType::sniff(b"[1,2,3]").expect("valid content type"),
            ContentType::Json
        );
    }

    #[test]
    fn sniff_xml() {
        assert_eq!(
            ContentType::sniff(b"<root/>").expect("valid content type"),
            ContentType::Xml
        );
    }

    #[test]
    fn sniff_form_encoded() {
        assert_eq!(
            ContentType::sniff(b"key=value&other=x").expect("valid content type"),
            ContentType::FormEncoded
        );
    }

    #[test]
    fn unrecognized_content_type_fails() {
        assert!(ContentType::sniff(b"some binary\x00data").is_err());
    }

    #[test]
    fn resolve_prefers_header_over_body_sniffing() {
        // The body looks like XML, but a conclusive header always wins.
        assert_eq!(
            ContentType::resolve(
                Some(
                    headers::ContentType::from_str("application/json").expect("valid content type")
                ),
                b"<root/>"
            )
            .expect("valid content type"),
            ContentType::Json
        );
    }

    #[test]
    fn resolve_falls_back_to_sniffing_when_header_is_absent() {
        assert_eq!(
            ContentType::resolve(None, b"<root/>").expect("valid content type"),
            ContentType::Xml
        );
    }

    // ── rehydrate_body ───────────────────────────────────────────────────────

    fn rehydrate(
        body: &[u8],
        ct: ContentType,
        ops: &[(&SecretPlaceholder, &SecretString)],
    ) -> Vec<u8> {
        // Build ops from (placeholder_bytes_range, secret) tuples; find each
        // placeholder in the body.
        let ops: Vec<RehydrateOp> = ops
            .iter()
            .filter_map(|(placeholder, secret)| {
                let ph = placeholder.to_string();
                body.windows(ph.len()).enumerate().find_map(|(i, w)| {
                    if w == ph.as_bytes() {
                        Some(RehydrateOp {
                            range: i..i + ph.len(),
                            secret,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();
        let mut sorted = ops;
        sorted.sort_by_key(|op| op.range.start);
        rehydrate_body(body, ct, &sorted)
    }

    #[test]
    fn rehydrate_json_body_escapes_quotes() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("{{\"token\":\"{placeholder}\"}}");
        let secret = SecretString::from("s\"ec\"ret");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::Json, &ops);
        let result_str = std::str::from_utf8(&result).expect("utf8");
        assert!(result_str.contains("s\\\"ec\\\"ret"), "got: {result_str}");
    }

    #[test]
    fn rehydrate_json_body_escapes_backslash() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("{{\"p\":\"{placeholder}\"}}");
        let secret = SecretString::from("a\\b");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::Json, &ops);
        let s = std::str::from_utf8(&result).expect("utf8");
        assert!(s.contains("a\\\\b"), "got: {s}");
    }

    #[test]
    fn rehydrate_form_body_percent_encodes() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("token={placeholder}&other=x");
        let secret = SecretString::from("p@ss w0rd");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::FormEncoded, &ops);
        let s = std::str::from_utf8(&result).expect("utf8");
        assert_eq!(s, "token=p%40ss+w0rd&other=x");
    }

    #[test]
    fn rehydrate_form_body_encodes_spaces_as_plus() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("token={placeholder}");
        let secret = SecretString::from("p@ss w+rd");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::FormEncoded, &ops);

        assert_eq!(result, b"token=p%40ss+w%2Brd");
    }

    #[test]
    fn rehydrate_xml_body_escapes_entities() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("<auth>{placeholder}</auth>");
        let secret = SecretString::from("<secret&>");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::Xml, &ops);
        let s = std::str::from_utf8(&result).expect("utf8");
        assert_eq!(s, "<auth>&lt;secret&amp;&gt;</auth>");
    }

    #[test]
    fn rehydrate_xml_attribute_escapes_both_quote_styles() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("<auth value='{placeholder}'/>");
        let secret = SecretString::from("a'b\"c");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::Xml, &ops);

        assert_eq!(result, b"<auth value='a&apos;b&quot;c'/>");
    }

    #[test]
    fn rehydrate_raw_body_passes_through_unchanged() {
        let placeholder = SecretPlaceholder::new();
        let body = format!("{placeholder}\x00data");
        let secret = SecretString::from("\x01\x02\x03");
        let ops = [(&placeholder, &secret)];
        let result = rehydrate(body.as_bytes(), ContentType::Raw, &ops);
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
        let placeholder = SecretPlaceholder::new();
        let ops = [MaskOp {
            range: 7..13,
            placeholder: &placeholder,
        }];
        let result = mask_body(body, &ops);
        assert_eq!(
            result,
            format!("token: {placeholder}, other: stuff").into_bytes()
        );
    }

    #[test]
    fn mask_multiple_occurrences() {
        let body = b"s3cr3t and s3cr3t again";
        let placeholder1 = SecretPlaceholder::new();
        let placeholder2 = SecretPlaceholder::new();
        let ops = [
            MaskOp {
                range: 0..6,
                placeholder: &placeholder1,
            },
            MaskOp {
                range: 11..17,
                placeholder: &placeholder2,
            },
        ];
        let result = mask_body(body, &ops);
        assert_eq!(
            result,
            format!("{placeholder1} and {placeholder2} again").into_bytes()
        );
    }

    #[test]
    fn mask_no_ops_returns_body_unchanged() {
        let body = b"no secrets here";
        assert_eq!(mask_body(body, &[]), body.as_slice());
    }

    // ── encoding edge cases ──────────────────────────────────────────────────

    #[test]
    fn json_escape_control_chars() {
        let result = json_escape(&SecretString::from("\x00\x01\x1F"));
        assert_eq!(result, "\\u0000\\u0001\\u001f");
    }

    #[test]
    fn json_escape_tab_newline_return() {
        assert_eq!(json_escape(&SecretString::from("\t\n\r")), "\\t\\n\\r");
    }

    #[test]
    fn json_escape_passes_through_valid_multibyte_utf8() {
        let input = SecretString::from("€ café");
        assert_eq!(json_escape(&input), input.expose_secret());
    }

    #[test]
    fn form_encode_unreserved_unchanged() {
        let input = SecretString::from("abcABC123-._*");
        assert_eq!(form_encode(&input), input.expose_secret());
    }

    #[test]
    fn form_encode_special_bytes() {
        let input = SecretString::from("a b+c");
        assert_eq!(form_encode(&input), "a+b%2Bc");
    }

    #[test]
    fn xml_escape_all_entities() {
        let input = SecretString::from("<a>&\"</a>");
        assert_eq!(xml_escape(&input), "&lt;a&gt;&amp;&quot;&lt;/a&gt;");
    }

    /// Models a decode-aware scanner: it locates the encoded span whose
    /// content-type-specific decoding matches `secret`, then hands the
    /// discovered range to `mask_body`.
    fn mask_one_canonical_spelling(
        body: &[u8],
        content_type: ContentType,
        secret: &SecretString,
        placeholder: &SecretPlaceholder,
    ) -> Vec<u8> {
        let spans = find_decoded_secret_spans(body, content_type, secret);

        let mut body = body.to_vec();
        for range in spans {
            body = mask_body(&body, &[MaskOp { range, placeholder }]);
        }
        body
    }

    #[test]
    fn mask_json_matches_decoded_secret_across_noncanonical_escape() {
        let secret = SecretString::from("a\"b");
        let placeholder = SecretPlaceholder::new();

        // `a\u0022b` and `a\"b` both decode to `a"b`, but serde_json's
        // canonical encoding uses the latter.
        let body = br#"{"token":"a\u0022b"}"#;
        let parsed: serde_json::Value = serde_json::from_slice(body).expect("valid JSON fixture");
        assert_eq!(
            parsed["token"].as_str(),
            Some(secret.expose_secret()),
            "fixture must contain the known secret semantically"
        );

        let result = mask_one_canonical_spelling(body, ContentType::Json, &secret, &placeholder);

        assert_eq!(
            String::from_utf8(result).expect("valid utf8"),
            format!(r#"{{"token":"{placeholder}"}}"#)
        );
    }

    #[test]
    fn mask_form_matches_decoded_secret_across_equivalent_percent_encoding() {
        let secret = SecretString::from("a b+c");
        let placeholder = SecretPlaceholder::new();

        // The canonical encoder produces `a+b%2Bc`; this uses `%20` for the
        // space and lowercase `%2b` for the literal plus.
        let body = b"token=a%20b%2bc";
        let (_, value) = form_urlencoded::parse(body)
            .next()
            .expect("form fixture contains one field");
        assert_eq!(
            value.as_ref(),
            secret.expose_secret(),
            "fixture must contain the known secret semantically"
        );

        let result =
            mask_one_canonical_spelling(body, ContentType::FormEncoded, &secret, &placeholder);

        assert_eq!(result, format!("token={placeholder}").into_bytes());
    }

    #[test]
    fn mask_xml_matches_decoded_secret_across_numeric_entity() {
        let secret = SecretString::from("a&b");
        let placeholder = SecretPlaceholder::new();

        // The canonical encoder produces `a&amp;b`; the hexadecimal numeric
        // entity below has the same XML character value.
        let encoded_secret = "a&#x26;b";
        let decoded =
            quick_xml::escape::unescape(encoded_secret).expect("valid XML entity fixture");
        assert_eq!(
            decoded.as_ref(),
            secret.expose_secret(),
            "fixture must contain the known secret semantically"
        );

        let body = format!("<token>{encoded_secret}</token>");
        let result =
            mask_one_canonical_spelling(body.as_bytes(), ContentType::Xml, &secret, &placeholder);

        assert_eq!(result, format!("<token>{placeholder}</token>").into_bytes());
    }

    #[test]
    fn mask_xml_matches_secret_in_attribute_value() {
        let secret = SecretString::from("a&b");
        let placeholder = SecretPlaceholder::new();

        let body = br#"<auth value="a&amp;b"/>"#;
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"<auth value="{placeholder}"/>"#).into_bytes()
        );
    }

    #[test]
    fn mask_xml_matches_secret_in_single_quoted_attribute_value() {
        let secret = SecretString::from("a'b\"c");
        let placeholder = SecretPlaceholder::new();

        let body = b"<auth value='a&apos;b&quot;c'/>";
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!("<auth value='{placeholder}'/>").into_bytes()
        );
    }

    #[test]
    fn mask_xml_matches_secret_embedded_in_longer_text_node() {
        // Regression: a secret embedded in a longer text node (e.g. an error
        // message surrounding the token) used to slip past the whole-node
        // equality check and stay unmasked.
        let secret = SecretString::from("sk-abc123def456");
        let placeholder = SecretPlaceholder::new();

        let body = b"<error>invalid token sk-abc123def456 supplied</error>";
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!("<error>invalid token {placeholder} supplied</error>").into_bytes()
        );
    }

    #[test]
    fn mask_xml_matches_secret_embedded_in_attribute_value() {
        // Regression: same embedded-secret gap for attribute values, which
        // previously matched only when the whole value equaled the secret.
        let secret = SecretString::from("sk-abc123def456");
        let placeholder = SecretPlaceholder::new();

        let body = br#"<link url="https://vault.example/x?token=sk-abc123def456&amp;x=1"/>"#;
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"<link url="https://vault.example/x?token={placeholder}&amp;x=1"/>"#)
                .into_bytes()
        );
    }

    #[test]
    fn mask_form_does_not_redact_suffix_after_secret_in_value() {
        // Regression: a value like `abcdefgh=x` (where `abcdefgh` is a known
        // secret) used to be matched by comparing the decoded *name* half of
        // the value, replacing the whole `abcdefgh=x` span and corrupting the
        // `=x` suffix. Only the secret bytes themselves may be redacted.
        let secret = SecretString::from("abcdefgh");
        let placeholder = SecretPlaceholder::new();

        let body = b"field=abcdefgh=x&other=1";
        let result =
            mask_one_canonical_spelling(body, ContentType::FormEncoded, &secret, &placeholder);

        assert_eq!(
            result,
            format!("field={placeholder}=x&other=1").into_bytes()
        );
    }

    // ── decoded substring matches (escaped secrets in longer content) ───────

    #[test]
    fn mask_json_matches_secret_with_escaped_bytes_embedded_in_longer_text() {
        // Regression: a secret whose own bytes are escaped (`\"`) was missed
        // by the raw word-bounded scan, and escaped literals only matched as
        // a whole value. The decoded scan maps the decoded span back to the
        // exact raw bytes, leaving the surrounding text and other escapes
        // untouched.
        let secret = SecretString::from("p@ss\"word");
        let placeholder = SecretPlaceholder::new();

        let body = br#"{"error":"tab\there p@ss\"word x"}"#;
        let result = mask_one_canonical_spelling(body, ContentType::Json, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"{{"error":"tab\there {placeholder} x"}}"#).into_bytes()
        );
    }

    #[test]
    fn mask_json_matches_secret_with_unicode_escape_embedded() {
        // `\u0022` is a noncanonical spelling of `"`; the decoded span for
        // the embedded secret maps to the full 6-byte escape.
        let secret = SecretString::from("sk-a\"b");
        let placeholder = SecretPlaceholder::new();

        let body = br#"{"token":"token sk-a\u0022b here"}"#;
        let result = mask_one_canonical_spelling(body, ContentType::Json, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"{{"token":"token {placeholder} here"}}"#).into_bytes()
        );
    }

    #[test]
    fn mask_json_matches_secret_with_surrogate_pair_escape_embedded() {
        // `\uD83D\uDE00` is the UTF-16 surrogate pair for `😀` (12 raw
        // bytes); the decoded span maps back to the whole pair.
        let secret = SecretString::from("pwd😀x");
        let placeholder = SecretPlaceholder::new();

        let body = br#"{"token":"cred pwd\uD83D\uDE00x end"}"#;
        let result = mask_one_canonical_spelling(body, ContentType::Json, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"{{"token":"cred {placeholder} end"}}"#).into_bytes()
        );
    }

    #[test]
    fn mask_json_skips_literal_with_invalid_escape() {
        // `\q` is not a valid JSON escape; the literal is treated as
        // unmatchable rather than risking a misaligned raw span, while a
        // valid escape in another literal still matches.
        let secret = SecretString::from("x\ny");
        let placeholder = SecretPlaceholder::new();

        let body = br#"{"ok":"x\ny","bad":"x\qz"}"#;
        let result = mask_one_canonical_spelling(body, ContentType::Json, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"{{"ok":"{placeholder}","bad":"x\qz"}}"#).into_bytes()
        );
    }

    #[test]
    fn mask_form_matches_percent_encoded_secret_embedded_in_longer_value() {
        // Regression: a percent-encoded secret embedded in a longer value was
        // missed entirely; the decoded scan maps the decoded span back to the
        // `%XX` bytes.
        let secret = SecretString::from("my secret here");
        let placeholder = SecretPlaceholder::new();

        let body = b"token=access my%20secret%20here granted&other=1";
        let result =
            mask_one_canonical_spelling(body, ContentType::FormEncoded, &secret, &placeholder);

        assert_eq!(
            result,
            format!("token=access {placeholder} granted&other=1").into_bytes()
        );
    }

    #[test]
    fn mask_form_matches_plus_encoded_secret_embedded() {
        // `+` is the canonical spelling of a space in form values.
        let secret = SecretString::from("a b");
        let placeholder = SecretPlaceholder::new();

        let body = b"token=x a+b y";
        let result =
            mask_one_canonical_spelling(body, ContentType::FormEncoded, &secret, &placeholder);

        assert_eq!(result, format!("token=x {placeholder} y").into_bytes());
    }

    #[test]
    fn mask_xml_matches_entity_escaped_secret_embedded_in_text_node() {
        // Regression: `a&amp;b` (the secret `a&b`) embedded in a longer text
        // node was missed by the raw scan; the decoded span maps back to the
        // full entity.
        let secret = SecretString::from("a&b");
        let placeholder = SecretPlaceholder::new();

        let body = b"<error>invalid token a&amp;b supplied</error>";
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!("<error>invalid token {placeholder} supplied</error>").into_bytes()
        );
    }

    #[test]
    fn mask_xml_matches_entity_escaped_secret_embedded_in_attribute_value() {
        // Two entities share the value; only the one the secret spans is
        // redacted, and only the secret's bytes (not the rest of the entity).
        let secret = SecretString::from("a&b");
        let placeholder = SecretPlaceholder::new();

        let body = br#"<link url="x?a&amp;b&amp;c=1"/>"#;
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!(r#"<link url="x?{placeholder}&amp;c=1"/>"#).into_bytes()
        );
    }

    #[test]
    fn mask_xml_matches_numeric_entity_escaped_secret_embedded() {
        // Decimal character reference, distinct from the hexadecimal entity
        // in the whole-value test.
        let secret = SecretString::from("a&b");
        let placeholder = SecretPlaceholder::new();

        let body = b"<error>bad token a&#38;b value</error>";
        let result = mask_one_canonical_spelling(body, ContentType::Xml, &secret, &placeholder);

        assert_eq!(
            result,
            format!("<error>bad token {placeholder} value</error>").into_bytes()
        );
    }

    #[test]
    fn mask_round_trips_through_canonical_encoder() {
        // The offset-map decoders must agree with the encoders `encode_secret`
        // uses: re-encoding the secret and masking the result redacts the
        // whole value for every content type.
        let secret = SecretString::from("a\"b&c<d> e+f");
        let placeholder = SecretPlaceholder::new();
        let cases = [
            (
                ContentType::Json,
                format!(
                    "{{\"token\":\"{}\"}}",
                    encode_secret(&secret, ContentType::Json)
                ),
                format!("{{\"token\":\"{placeholder}\"}}").into_bytes(),
            ),
            (
                ContentType::FormEncoded,
                format!("token={}", encode_secret(&secret, ContentType::FormEncoded)),
                format!("token={placeholder}").into_bytes(),
            ),
            (
                ContentType::Xml,
                format!(
                    "<token>{}</token>",
                    encode_secret(&secret, ContentType::Xml)
                ),
                format!("<token>{placeholder}</token>").into_bytes(),
            ),
        ];
        for (content_type, body, expected) in cases {
            let result =
                mask_one_canonical_spelling(body.as_bytes(), content_type, &secret, &placeholder);
            assert_eq!(result, expected, "content type {content_type:?}");
        }
    }

    #[test]
    fn decode_json_content_matches_serde_json() {
        for content in [
            "plain",
            "with \\\"quotes\\\"",
            "a\\u0022b",
            "tab\\t and \\nnewline",
            "emoji \\uD83D\\uDE00 done",
            "\\u0000 null",
        ] {
            let decoded = decode_json_content(content.as_bytes()).expect("valid escape");
            let via_serde = serde_json::from_str::<String>(&format!("\"{content}\""))
                .expect("valid JSON string literal");
            assert_eq!(
                std::str::from_utf8(&decoded.decoded).expect("valid utf8"),
                via_serde,
                "for {content}"
            );
        }
    }

    #[test]
    fn decode_xml_content_matches_quick_xml() {
        for raw in [
            "plain text",
            "a&amp;b",
            "a&#38;b",
            "a&#x26;b",
            "both &lt;tag&gt; and &quot;quote&quot;",
            "&amp;amp; nested",
        ] {
            let decoded = decode_xml_content(raw.as_bytes());
            let via_quick = quick_xml::escape::unescape(raw).expect("valid XML entity fixture");
            assert_eq!(
                std::str::from_utf8(&decoded.decoded).expect("valid utf8"),
                via_quick.as_ref(),
                "for {raw}"
            );
        }
    }

    #[test]
    fn decode_form_content_matches_form_urlencoded() {
        for raw in [
            "plain",
            "a%20b+c",
            "%2B plus %2b lower",
            "100%25 off",
            "bad %zz kept",
            "trailing%",
        ] {
            let decoded = decode_form_content(raw.as_bytes());
            let (name, _) = form_urlencoded::parse(raw.as_bytes())
                .next()
                .expect("one field");
            assert_eq!(
                std::str::from_utf8(&decoded.decoded).expect("valid utf8"),
                name.as_ref(),
                "for {raw}"
            );
        }
    }
}
