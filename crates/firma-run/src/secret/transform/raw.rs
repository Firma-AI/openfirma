//! `raw` streaming byte rewriter for the redact transform.
//!
//! Rehydration and masking are the same operation — find non-overlapping
//! leftmost-longest matches of a pattern set and replace their spans — run
//! incrementally over a stream.
//!
//! Streaming makes one detail load-bearing: a pattern can straddle a read
//! boundary. The rewriter carries an **overlap buffer** of `maxPatternLen - 1`
//! bytes across reads, so a token or secret split between two chunks still
//! matches. Output is therefore a pure function of the input bytes, independent
//! of how the stream was chunked. See `docs/architecture/secrets-interception.md`.

use std::io::{self, Read, Write};

use either::Either;

use super::Direction;
use crate::secret::SecretStore;

/// A resolved replacement span within the working buffer.
struct Replacement<'a> {
    start: usize,
    end: usize,
    with: &'a [u8],
}

/// Copy `reader` to `writer`, applying the `direction` rewrite over `store`.
///
/// Reads in fixed chunks and rewrites incrementally with an overlap buffer, so
/// the result does not depend on the chunk boundaries the reader happens to
/// produce. An empty store passes the stream through unchanged.
///
/// # Errors
///
/// Returns any I/O error from reading `reader` or writing `writer`.
pub fn stream_raw<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    store: &SecretStore,
    direction: Direction,
) -> io::Result<()> {
    let max_pattern_len = match direction {
        Direction::Rehydrate => store.max_placeholder_len(),
        Direction::Mask => store.max_secret_len(),
    };
    let mut state = StreamState::new(max_pattern_len);
    let mut chunk = [0u8; 8192];
    let mut out = Vec::new();

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        out.clear();
        state.push(&chunk[..read], store, direction, &mut out);
        writer.write_all(&out)?;
    }

    out.clear();
    state.finish(store, direction, &mut out);
    writer.write_all(&out)?;
    writer.flush()
}

/// Incremental rewrite state: the retained overlap buffer and the pattern-length
/// bound that determines how much to retain.
struct StreamState {
    /// Bytes carried over from the previous chunk (a possible partial match).
    carry: Vec<u8>,
    /// Longest pattern length; the overlap buffer retains `max - 1` bytes.
    max_pattern_len: usize,
}

impl StreamState {
    fn new(max_pattern_len: usize) -> Self {
        Self {
            carry: Vec::new(),
            max_pattern_len,
        }
    }

    /// Consume `chunk`, appending the committed output to `out`.
    ///
    /// A match is committed only when it ends before the danger zone — the final
    /// `max_pattern_len - 1` bytes, which could still grow into a longer match
    /// once more input arrives. Everything from the first match that reaches the
    /// danger zone (or the danger-zone start, whichever is earlier) is retained.
    fn push(&mut self, chunk: &[u8], store: &SecretStore, direction: Direction, out: &mut Vec<u8>) {
        let mut buffer = std::mem::take(&mut self.carry);
        buffer.extend_from_slice(chunk);

        let retain = self.max_pattern_len.saturating_sub(1);
        let danger_start = buffer.len().saturating_sub(retain);

        let mut cursor = 0;
        // Default: retain only the trailing `retain` bytes (a match could begin
        // anywhere in there and complete with the next chunk).
        let mut retain_from = buffer.len();
        for replacement in matches(store, direction, &buffer) {
            if replacement.end > danger_start {
                // This match touches the danger zone: it might extend further
                // with the next chunk, so retain from its start and re-evaluate.
                retain_from = replacement.start.max(cursor);
                break;
            }
            out.extend_from_slice(&buffer[cursor..replacement.start]);
            out.extend_from_slice(replacement.with);
            cursor = replacement.end;
        }

        let safe_end = retain_from.min(danger_start).max(cursor);
        out.extend_from_slice(&buffer[cursor..safe_end]);
        self.carry = buffer[safe_end..].to_vec();
    }

    /// Flush the retained buffer at end of stream, committing every match.
    fn finish(self, store: &SecretStore, direction: Direction, out: &mut Vec<u8>) {
        let buffer = self.carry;
        let mut cursor = 0;
        for replacement in matches(store, direction, &buffer) {
            out.extend_from_slice(&buffer[cursor..replacement.start]);
            out.extend_from_slice(replacement.with);
            cursor = replacement.end;
        }
        out.extend_from_slice(&buffer[cursor..]);
    }
}

/// Resolve the replacement spans for `buffer` in the given direction.
fn matches<'a>(
    store: &'a SecretStore,
    direction: Direction,
    buffer: &'a [u8],
) -> impl Iterator<Item = Replacement<'a>> + 'a {
    match direction {
        Direction::Rehydrate => {
            Either::Left(store.rehydrate_matches(buffer).map(|m| Replacement {
                start: m.start,
                end: m.end,
                with: m.secret,
            }))
        }
        Direction::Mask => Either::Right(store.mask_matches(buffer).map(|m| Replacement {
            start: m.start,
            end: m.end,
            with: m.placeholder.as_str().as_bytes(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::secret::{Placeholder, SecretValue};

    /// A `Read` that hands out at most the next configured chunk size per call,
    /// cycling through `sizes`. Used to prove chunk-boundary invariance.
    struct ChunkReader<'a> {
        data: &'a [u8],
        pos: usize,
        sizes: Vec<usize>,
        step: usize,
    }

    impl<'a> ChunkReader<'a> {
        fn new(data: &'a [u8], sizes: Vec<usize>) -> Self {
            Self {
                data,
                pos: 0,
                sizes,
                step: 0,
            }
        }
    }

    impl Read for ChunkReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let want = self.sizes[self.step % self.sizes.len()].max(1);
            self.step += 1;
            let n = want.min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn run(store: &SecretStore, direction: Direction, input: &[u8], sizes: Vec<usize>) -> Vec<u8> {
        let mut reader = ChunkReader::new(input, sizes);
        let mut out = Vec::new();
        stream_raw(&mut reader, &mut out, store, direction).expect("stream rewrite");
        out
    }

    fn store_with(entries: &[(&str, &str)]) -> SecretStore {
        let mut store = SecretStore::new();
        for (name, value) in entries {
            store
                .insert(Placeholder::mint("bw", name), SecretValue::from(*value))
                .expect("insert secret");
        }
        store
    }

    #[test]
    fn rehydrate_replaces_known_token_and_passes_unknown_through() {
        let store = store_with(&[("db", "s3cr3t")]);
        let token = Placeholder::mint("bw", "db");
        let input = format!("user=admin pass={token} note=firma-secret://bw/unknown");

        let out = run(
            &store,
            Direction::Rehydrate,
            input.as_bytes(),
            vec![input.len()],
        );
        assert_eq!(
            out,
            b"user=admin pass=s3cr3t note=firma-secret://bw/unknown"
        );
    }

    #[test]
    fn mask_replaces_secret_with_placeholder() {
        let store = store_with(&[("db", "s3cr3t")]);
        let token = Placeholder::mint("bw", "db");

        let out = run(&store, Direction::Mask, b"leaked s3cr3t here", vec![64]);
        assert_eq!(out, format!("leaked {token} here").into_bytes());
    }

    #[test]
    fn empty_store_passes_through_both_directions() {
        let store = SecretStore::new();
        let input = b"firma-secret://bw/db and plain text";
        assert_eq!(
            run(&store, Direction::Rehydrate, input, vec![3]),
            input.to_vec()
        );
        assert_eq!(run(&store, Direction::Mask, input, vec![3]), input.to_vec());
    }

    #[test]
    fn token_split_across_reads_is_rehydrated() {
        let store = store_with(&[("db", "s3cr3t")]);
        let token = Placeholder::mint("bw", "db");
        let input = token.as_str().as_bytes().to_vec();

        // One byte at a time: the token only completes across many reads.
        let out = run(&store, Direction::Rehydrate, &input, vec![1]);
        assert_eq!(out, b"s3cr3t");
    }

    #[test]
    fn secret_split_across_reads_is_masked() {
        let store = store_with(&[("db", "abcdef")]);
        let token = Placeholder::mint("bw", "db");

        let out = run(&store, Direction::Mask, b"xxabcdefxx", vec![1]);
        assert_eq!(out, format!("xx{token}xx").into_bytes());
    }

    proptest! {
        /// Masking output is identical regardless of how the stream is chunked,
        /// and equal to the whole-input reference rewrite.
        #[test]
        fn mask_is_chunk_split_invariant(
            input in prop::collection::vec(prop::sample::select(vec![b'a', b'b', b'c', b'X']), 0..128),
            sizes in prop::collection::vec(1usize..9, 1..8),
        ) {
            // "abcab" is self-overlapping, so matches cluster and straddle reads.
            let store = store_with(&[("s", "abcab"), ("t", "bc")]);
            let expected = reference_impl(&store, Direction::Mask, &input);
            let streamed = run(&store, Direction::Mask, &input, sizes);
            prop_assert_eq!(streamed, expected);
        }

        /// Rehydration output is identical regardless of chunking, and equal to
        /// the whole-input reference rewrite.
        #[test]
        fn rehydrate_is_chunk_split_invariant(
            filler in prop::collection::vec(prop::sample::select(vec![b'a', b'b', b' ']), 0..64),
            insertions in prop::collection::vec(0usize..3, 0..8),
            sizes in prop::collection::vec(1usize..9, 1..8),
        ) {
            let store = store_with(&[("one", "SECRET-ONE"), ("two", "S2")]);
            let tokens = [
                Placeholder::mint("bw", "one").as_str().to_owned(),
                Placeholder::mint("bw", "two").as_str().to_owned(),
                "firma-secret://bw/unknown".to_owned(),
            ];
            // Interleave filler bytes with placeholder tokens at chosen points.
            let mut input = filler.clone();
            for &which in &insertions {
                input.extend_from_slice(tokens[which].as_bytes());
                input.extend_from_slice(&filler);
            }
            let expected = reference_impl(&store, Direction::Rehydrate, &input);
            let streamed = run(&store, Direction::Rehydrate, &input, sizes);
            prop_assert_eq!(streamed, expected);
        }
    }

    /// Whole-input reference rewrite: splice non-overlapping matches in order.
    fn reference_impl(store: &SecretStore, direction: Direction, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cursor = 0;
        for replacement in matches(store, direction, input) {
            out.extend_from_slice(&input[cursor..replacement.start]);
            out.extend_from_slice(replacement.with);
            cursor = replacement.end;
        }
        out.extend_from_slice(&input[cursor..]);
        out
    }
}
