//! `Content-Encoding` aware body decode/encode for secret placeholder
//! rehydration and secret masking.
//!
//! Request and response bodies inspected for secrets (placeholder tokens on
//! the way out, leaked/echoed values on the way back) must be scanned as
//! plaintext, but may arrive or need to be forwarded compressed. This module
//! decodes a supported `Content-Encoding` before scanning and re-encodes
//! afterward so the forwarded body's declared encoding still matches its
//! bytes.
//!
//! Decode/encode run on `tokio::task::spawn_blocking` rather than inline, so
//! the CPU-bound (de)compression work never blocks the async task's worker
//! thread — mirroring this crate's existing convention for offloading
//! synchronous work from an async context (see Cedar policy evaluation in
//! `enforcement::constraint_enforcement`). Bodies here are already fully
//! buffered `Vec<u8>` by the time this module sees them, so an async
//! (de)compression adapter over an in-memory buffer would still run
//! synchronously during `poll()` without a real streaming source to await on
//! — `spawn_blocking` is what actually avoids blocking a worker thread.

use std::borrow::Cow;
use std::io::{Read, Write};

use firma_http::HeaderMap;
use thiserror::Error;

/// RFC 7230 defines HTTP `deflate` as the zlib format
/// (RFC 1950), but many servers historically send raw
/// DEFLATE (RFC 1951). Try the zlib wrapper first, then fall
/// back to raw DEFLATE, so either server behavior decodes.
/// A mislabeled payload fails the zlib Adler-32 checksum, so
/// an accidental zlib decode of raw-DEFLATE data is caught
/// and retried raw rather than silently trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum DeflateEncoding {
    #[default]
    Deflate,
    Zlib,
}

/// A `Content-Encoding` this layer knows how to reversibly decode before
/// running the plaintext secret matcher, and re-encode afterward so a
/// forwarded body's declared encoding still matches its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupportedEncoding {
    Gzip,
    Deflate(DeflateEncoding),
    Brotli,
    Zstd,
}

impl SupportedEncoding {
    /// Reads `headers`' `Content-Encoding`. `Ok(None)` covers both an absent
    /// header and `identity`. `Err` carries the encoding name when it's
    /// present but not one this layer can decode — the body must then be
    /// treated as opaque rather than scanned or forwarded unexamined.
    fn from_headers(headers: &HeaderMap) -> Result<Option<Self>, String> {
        let Some(value) = headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(None);
        };
        match value.trim() {
            "" | "identity" => Ok(None),
            "gzip" => Ok(Some(Self::Gzip)),
            "deflate" => Ok(Some(Self::Deflate(DeflateEncoding::default()))),
            "br" => Ok(Some(Self::Brotli)),
            "zstd" => Ok(Some(Self::Zstd)),
            other => Err(other.to_string()),
        }
    }

    fn decode(
        &mut self,
        body: &[u8],
        max_decompressed_bytes: usize,
    ) -> Result<Vec<u8>, BodyEncodingError> {
        match self {
            Self::Gzip => {
                bounded_read_to_end(flate2::read::GzDecoder::new(body), max_decompressed_bytes)
            }
            Self::Deflate(encoding) => {
                bounded_read_to_end(flate2::read::ZlibDecoder::new(body), max_decompressed_bytes)
                    .inspect(|_| {
                        *encoding = DeflateEncoding::Zlib;
                    })
                    .map_or_else(
                        |_| {
                            bounded_read_to_end(
                                flate2::read::DeflateDecoder::new(body),
                                max_decompressed_bytes,
                            )
                            .inspect(|_| {
                                *encoding = DeflateEncoding::Deflate;
                            })
                        },
                        Ok,
                    )
            }
            Self::Brotli => bounded_read_to_end(
                brotli::Decompressor::new(body, 4096),
                max_decompressed_bytes,
            ),
            Self::Zstd => {
                let decoder =
                    zstd::stream::read::Decoder::new(body).map_err(BodyEncodingError::Decode)?;
                bounded_read_to_end(decoder, max_decompressed_bytes)
            }
        }
    }

    fn encode(self, body: &[u8]) -> Result<Vec<u8>, BodyEncodingError> {
        match self {
            Self::Gzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(body).map_err(BodyEncodingError::Encode)?;
                encoder.finish().map_err(BodyEncodingError::Encode)
            }
            Self::Deflate(encoding) => match encoding {
                DeflateEncoding::Deflate => {
                    let mut encoder = flate2::write::DeflateEncoder::new(
                        Vec::new(),
                        flate2::Compression::default(),
                    );
                    encoder.write_all(body).map_err(BodyEncodingError::Encode)?;
                    encoder.finish().map_err(BodyEncodingError::Encode)
                }
                DeflateEncoding::Zlib => {
                    let mut encoder =
                        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    encoder.write_all(body).map_err(BodyEncodingError::Encode)?;
                    encoder.finish().map_err(BodyEncodingError::Encode)
                }
            },
            Self::Brotli => {
                // Quality 5 of 11: this recompression runs per-request on
                // the enforcement hot path (off the async worker thread via
                // spawn_blocking, but still real CPU time), so throughput is
                // favored over maximal compression ratio.
                let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
                writer.write_all(body).map_err(BodyEncodingError::Encode)?;
                Ok(writer.into_inner())
            }
            Self::Zstd => {
                let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0)
                    .map_err(BodyEncodingError::Encode)?;
                encoder.write_all(body).map_err(BodyEncodingError::Encode)?;
                encoder.finish().map_err(BodyEncodingError::Encode)
            }
        }
    }
}

/// Reads all of `reader` into a `Vec`, failing rather than allocating past
/// `max_decompressed_bytes` — a decompression bomb (a small compressed
/// payload that expands enormously) must not be able to force an unbounded
/// allocation here.
fn bounded_read_to_end<R: Read>(
    reader: R,
    max_decompressed_bytes: usize,
) -> Result<Vec<u8>, BodyEncodingError> {
    let mut out = Vec::new();
    reader
        .take(max_decompressed_bytes as u64 + 1)
        .read_to_end(&mut out)
        .map_err(BodyEncodingError::Decode)?;
    if out.len() > max_decompressed_bytes {
        return Err(BodyEncodingError::DecompressedTooLarge {
            limit: max_decompressed_bytes,
        });
    }
    Ok(out)
}

#[derive(Debug, Error)]
pub(crate) enum BodyEncodingError {
    #[error("content-encoding \"{0}\" cannot be decoded by this layer")]
    UnsupportedEncoding(String),
    #[error("failed to decompress body: {0}")]
    Decode(#[source] std::io::Error),
    #[error("decompressed body exceeds the {limit}-byte limit")]
    DecompressedTooLarge { limit: usize },
    #[error("failed to compress body: {0}")]
    Encode(#[source] std::io::Error),
    #[error("background (de)compression task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Resolves `body` to a plaintext view the secret matcher can scan, decoding
/// a supported `Content-Encoding` first, and returns the encoding alongside
/// it so the caller can re-encode after rewriting.
///
/// Borrows `body` unchanged (no `spawn_blocking`, no copy) when there's no
/// `Content-Encoding` to decode — the common case. Errs (fail closed) when
/// the encoding isn't one this layer can decode, or when decoding a
/// supported one fails — either way the body can't be inspected, so it must
/// not be forwarded unexamined.
pub(crate) async fn decode_body<'a>(
    body: &'a [u8],
    headers: &HeaderMap,
    max_decompressed_bytes: usize,
) -> Result<(Cow<'a, [u8]>, Option<SupportedEncoding>), BodyEncodingError> {
    let Some(mut encoding) =
        SupportedEncoding::from_headers(headers).map_err(BodyEncodingError::UnsupportedEncoding)?
    else {
        return Ok((Cow::Borrowed(body), None));
    };
    let owned = body.to_vec();
    let (decoded, encoding) = tokio::task::spawn_blocking(move || {
        let decoded = encoding.decode(&owned, max_decompressed_bytes)?;
        Ok::<_, BodyEncodingError>((decoded, encoding))
    })
    .await??;
    Ok((Cow::Owned(decoded), Some(encoding)))
}

/// Re-encodes a rewritten body back to `encoding` (a no-op when `None`) so
/// the forwarded body's declared `Content-Encoding` still matches its bytes.
pub(crate) async fn encode_body(
    plaintext: Vec<u8>,
    encoding: Option<SupportedEncoding>,
) -> Result<Vec<u8>, BodyEncodingError> {
    let Some(encoding) = encoding else {
        return Ok(plaintext);
    };
    tokio::task::spawn_blocking(move || encoding.encode(&plaintext)).await?
}

#[cfg(test)]
mod tests {
    use firma_http::HeaderMap;

    use super::*;

    fn headers_with_encoding(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-encoding",
            http::HeaderValue::from_str(value).expect("valid header value"),
        );
        headers
    }

    #[test]
    fn from_headers_absent_is_none() {
        assert_eq!(SupportedEncoding::from_headers(&HeaderMap::new()), Ok(None));
    }

    #[test]
    fn from_headers_identity_is_none() {
        assert_eq!(
            SupportedEncoding::from_headers(&headers_with_encoding("identity")),
            Ok(None)
        );
    }

    #[test]
    fn from_headers_unsupported_is_err() {
        assert_eq!(
            SupportedEncoding::from_headers(&headers_with_encoding("compress")),
            Err("compress".to_string())
        );
    }

    #[tokio::test]
    async fn decode_body_without_encoding_borrows() {
        let body = b"plaintext body";
        let (decoded, encoding) = decode_body(body, &HeaderMap::new(), 1024)
            .await
            .expect("decode succeeds");
        assert_eq!(decoded.as_ref(), body);
        assert_eq!(encoding, None);
        assert!(matches!(decoded, Cow::Borrowed(_)));
    }

    async fn roundtrip(encoding: SupportedEncoding, header_value: &str) {
        let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(8);
        let encoded = encode_body(plaintext.clone(), Some(encoding.clone()))
            .await
            .expect("encode succeeds");
        let (decoded, decoded_encoding) =
            decode_body(&encoded, &headers_with_encoding(header_value), 1024 * 1024)
                .await
                .expect("decode succeeds");
        assert_eq!(decoded.as_ref(), plaintext.as_slice());
        assert_eq!(decoded_encoding, Some(encoding));
    }

    #[tokio::test]
    async fn gzip_roundtrip() {
        roundtrip(SupportedEncoding::Gzip, "gzip").await;
    }

    #[tokio::test]
    async fn deflate_roundtrip() {
        roundtrip(
            SupportedEncoding::Deflate(DeflateEncoding::Deflate),
            "deflate",
        )
        .await;
    }

    #[tokio::test]
    async fn deflate_accepts_zlib_wrapped_stream() {
        // RFC 7230 defines HTTP `deflate` as the zlib format (RFC 1950);
        // the encoder here emits raw DEFLATE (RFC 1951). Decoding must
        // accept the conforming zlib-wrapped form, not just the encoder's
        // own raw output.
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let plaintext = b"zlib-wrapped deflate payload".repeat(4);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&plaintext).expect("encode succeeds");
        let compressed = encoder.finish().expect("finish succeeds");

        let (decoded, encoding) =
            decode_body(&compressed, &headers_with_encoding("deflate"), 1024 * 1024)
                .await
                .expect("zlib-wrapped deflate decodes");
        assert_eq!(decoded.as_ref(), plaintext.as_slice());
        assert_eq!(
            encoding,
            Some(SupportedEncoding::Deflate(DeflateEncoding::Zlib))
        );
    }

    #[tokio::test]
    async fn brotli_roundtrip() {
        roundtrip(SupportedEncoding::Brotli, "br").await;
    }

    #[tokio::test]
    async fn zstd_roundtrip() {
        roundtrip(SupportedEncoding::Zstd, "zstd").await;
    }

    #[tokio::test]
    async fn decode_body_rejects_encoding_over_limit() {
        let plaintext = vec![b'x'; 4096];
        let encoded = encode_body(plaintext, Some(SupportedEncoding::Gzip))
            .await
            .expect("encode succeeds");
        let error = decode_body(&encoded, &headers_with_encoding("gzip"), 1024)
            .await
            .expect_err("decompressed size exceeds the limit");
        assert!(matches!(
            error,
            BodyEncodingError::DecompressedTooLarge { limit: 1024 }
        ));
    }
}
