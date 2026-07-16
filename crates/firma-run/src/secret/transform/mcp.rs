//! `mcp-jsonrpc` streaming transform for MCP stdio servers.
//!
//! MCP over stdio frames one JSON-RPC message per line (`\n`-delimited). This
//! codec buffers each line, rewrites it, and re-emits it, so a message split
//! across reads is reassembled before substitution. Substitution is
//! escaping-aware because a secret lives inside a JSON string:
//!
//! - **rehydration** replaces a placeholder token (which never needs escaping)
//!   with the JSON-escaped secret, so quotes, backslashes, or newlines in the
//!   secret cannot corrupt the message;
//! - **masking** matches each secret in its JSON-escaped on-wire form and
//!   replaces it with the placeholder token.
//!
//! Raw byte substitution would be unsafe here: an unescaped secret produces
//! invalid JSON, and an escaped secret on stdout would be missed by a literal
//! search. Fail-closed: an unknown placeholder is never substituted. See
//! `docs/architecture/secrets-interception.md`.

use std::io::{self, Read, Write};

use aho_corasick::{AhoCorasick, MatchKind};
use arc_swap::ArcSwap;

use super::Direction;
use crate::secret::{Placeholder, SecretStore};

/// Copy `reader` to `writer` line by line, applying the `direction` rewrite in
/// JSON string context.
///
/// Lines are `\n`-delimited; the final line may lack a trailing newline. An
/// empty store passes the stream through unchanged.
///
/// # Errors
///
/// Returns an I/O error from reading `reader` or writing `writer`, or if the
/// masking automaton cannot be built (fail closed).
pub fn stream_mcp_jsonrpc<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    store: &ArcSwap<SecretStore>,
    direction: Direction,
) -> io::Result<()> {
    let mask_table = match direction {
        Direction::Mask => MaskTable::build(store)?,
        Direction::Rehydrate => None,
    };

    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut out = Vec::new();

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        pending.extend_from_slice(&chunk[..read]);

        out.clear();
        let mut consumed = 0;
        while let Some(offset) = pending[consumed..].iter().position(|&b| b == b'\n') {
            let end = consumed + offset;
            rewrite_line(
                store,
                direction,
                mask_table.as_ref(),
                &pending[consumed..end],
                &mut out,
            );
            out.push(b'\n');
            consumed = end + 1;
        }
        pending.drain(..consumed);
        writer.write_all(&out)?;
    }

    if !pending.is_empty() {
        out.clear();
        rewrite_line(store, direction, mask_table.as_ref(), &pending, &mut out);
        writer.write_all(&out)?;
    }
    writer.flush()
}

/// Rewrite a single framed line into `out` (without the trailing newline).
fn rewrite_line(
    store: &ArcSwap<SecretStore>,
    direction: Direction,
    mask_table: Option<&MaskTable>,
    line: &[u8],
    out: &mut Vec<u8>,
) {
    match direction {
        Direction::Rehydrate => {
            let mut cursor = 0;
            for m in store.load().rehydrate_matches(line) {
                out.extend_from_slice(&line[cursor..m.start]);
                out.extend_from_slice(&json_escape(m.secret));
                cursor = m.end;
            }
            out.extend_from_slice(&line[cursor..]);
        }
        Direction::Mask => match mask_table {
            Some(table) => table.mask_into(line, out),
            None => out.extend_from_slice(line),
        },
    }
}

/// Aho-Corasick automaton over the JSON-escaped on-wire form of each secret,
/// aligned to the placeholder each maps to.
struct MaskTable {
    matcher: AhoCorasick,
    placeholders: Vec<Placeholder>,
}

impl MaskTable {
    /// Build the escaped-secret automaton, or `None` if there is nothing to mask.
    fn build(store: &ArcSwap<SecretStore>) -> io::Result<Option<Self>> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut placeholders: Vec<Placeholder> = Vec::new();
        for (placeholder, secret) in store.load().iter() {
            if secret.is_empty() {
                continue;
            }
            patterns.push(json_escape(secret));
            placeholders.push(placeholder.clone());
        }
        if patterns.is_empty() {
            return Ok(None);
        }
        let matcher = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .map_err(io::Error::other)?;
        Ok(Some(Self {
            matcher,
            placeholders,
        }))
    }

    fn mask_into(&self, line: &[u8], out: &mut Vec<u8>) {
        let mut cursor = 0;
        for m in self.matcher.find_iter(line) {
            if let Some(placeholder) = self.placeholders.get(m.pattern().as_usize()) {
                out.extend_from_slice(&line[cursor..m.start()]);
                out.extend_from_slice(placeholder.as_str().as_bytes());
                cursor = m.end();
            }
        }
        out.extend_from_slice(&line[cursor..]);
    }
}

/// Encode `bytes` as they would appear inside a JSON string (between the
/// quotes), matching `serde_json`/`JSON.stringify` escaping.
fn json_escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0d => out.extend_from_slice(b"\\r"),
            control if control < 0x20 => {
                out.extend_from_slice(format!("\\u{control:04x}").as_bytes());
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::secret::SecretValue;

    /// A `Read` that yields at most `chunk` bytes per call, to force line
    /// reassembly across reads.
    struct ChunkReader<'a> {
        data: &'a [u8],
        pos: usize,
        chunk: usize,
    }

    impl Read for ChunkReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn run(
        store: &ArcSwap<SecretStore>,
        direction: Direction,
        input: &[u8],
        chunk: usize,
    ) -> Vec<u8> {
        let mut reader = ChunkReader {
            data: input,
            pos: 0,
            chunk,
        };
        let mut out = Vec::new();
        stream_mcp_jsonrpc(&mut reader, &mut out, store, direction).expect("mcp rewrite");
        out
    }

    fn store_with(entries: &[(&str, &str)]) -> ArcSwap<SecretStore> {
        let mut store = SecretStore::new();
        for (name, value) in entries {
            store
                .insert(Placeholder::mint("bw", name), SecretValue::from(*value))
                .expect("insert secret");
        }
        ArcSwap::from_pointee(store)
    }

    #[test]
    fn json_escape_matches_serde() {
        // The escaped form is exactly what serde_json emits between the quotes.
        let raw = "a\"b\\c\nd\te\x01";
        let escaped = json_escape(raw.as_bytes());
        let serde = serde_json::to_string(raw).expect("serialize");
        assert_eq!(escaped, &serde.as_bytes()[1..serde.len() - 1]);
    }

    #[test]
    fn rehydrate_escapes_secret_so_message_stays_valid_json() {
        let store = store_with(&[("pw", "pa\"ss\nword")]);
        let token = Placeholder::mint("bw", "pw");
        let input = format!("{{\"password\":\"{token}\"}}\n");

        let out = run(&store, Direction::Rehydrate, input.as_bytes(), 4096);
        let parsed: Value = serde_json::from_slice(out.strip_suffix(b"\n").unwrap())
            .expect("rehydrated line must stay valid JSON");
        assert_eq!(parsed["password"], json!("pa\"ss\nword"));
    }

    #[test]
    fn mask_matches_escaped_on_wire_form() {
        let store = store_with(&[("pw", "pa\"ss")]);
        let token = Placeholder::mint("bw", "pw");
        // A tool serializes the secret; on the wire the quote is escaped.
        let wire = serde_json::to_string(&json!({ "echo": "pa\"ss" })).expect("serialize");

        let out = run(
            &store,
            Direction::Mask,
            format!("{wire}\n").as_bytes(),
            4096,
        );
        let parsed: Value = serde_json::from_slice(out.strip_suffix(b"\n").unwrap())
            .expect("masked line stays valid JSON");
        assert_eq!(parsed["echo"], json!(token.as_str()));
        assert!(
            !out.windows(5).any(|w| w == b"pa\\\"s"),
            "escaped secret must not survive in output"
        );
    }

    #[test]
    fn mask_replaces_plain_secret() {
        let store = store_with(&[("v", "s3cr3t")]);
        let token = Placeholder::mint("bw", "v");
        let out = run(&store, Direction::Mask, b"{\"v\":\"s3cr3t\"}\n", 4096);
        assert_eq!(out, format!("{{\"v\":\"{token}\"}}\n").into_bytes());
    }

    #[test]
    fn line_split_across_reads_is_reassembled() {
        let store = store_with(&[("pw", "s3cr3t")]);
        let token = Placeholder::mint("bw", "pw");
        let input = format!("{{\"a\":\"{token}\"}}\n{{\"b\":\"{token}\"}}\n");

        // One byte per read: every line and token straddles many reads.
        let out = run(&store, Direction::Rehydrate, input.as_bytes(), 1);
        assert_eq!(out, b"{\"a\":\"s3cr3t\"}\n{\"b\":\"s3cr3t\"}\n");
    }

    #[test]
    fn final_line_without_newline_is_flushed() {
        let store = store_with(&[("pw", "s3cr3t")]);
        let token = Placeholder::mint("bw", "pw");
        // Second message has no trailing newline; it must still be rewritten.
        let input = format!("{{\"a\":\"{token}\"}}\n{{\"b\":\"{token}\"}}");

        let out = run(&store, Direction::Rehydrate, input.as_bytes(), 7);
        assert_eq!(out, b"{\"a\":\"s3cr3t\"}\n{\"b\":\"s3cr3t\"}");
    }

    #[test]
    fn unknown_placeholder_passes_through() {
        let store = store_with(&[("pw", "s3cr3t")]);
        let input = b"{\"x\":\"firma-secret://bw/unknown\"}\n";
        let out = run(&store, Direction::Rehydrate, input, 4096);
        assert_eq!(out, input);
    }

    #[test]
    fn empty_store_passes_through_both_directions() {
        let store = store_with(&[]);
        let input = b"{\"x\":\"firma-secret://bw/pw\"}\nplain\n";
        assert_eq!(run(&store, Direction::Rehydrate, input, 5), input);
        assert_eq!(run(&store, Direction::Mask, input, 5), input);
    }
}
