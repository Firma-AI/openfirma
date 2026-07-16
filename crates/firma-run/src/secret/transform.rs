//! Streaming redact transforms for a wrapped tool's stdio.
//!
//! Redaction rewrites a sanctioned tool's streams in both directions:
//! placeholders on the tool's **stdin** are rehydrated into real secrets, and
//! secrets on its **stdout** are masked back into placeholders. The policy's
//! `@transform` selects the codec:
//!
//! - [`transform::raw`] — byte-level streaming with an overlap buffer, for
//! opaque byte streams;
//! - [`transform::mcp`] — newline-delimited JSON-RPC, which substitutes inside
//! JSON string context (escaping-aware) so a rewritten message stays valid JSON.
//!
//! Both codecs share the [`transform::Direction`] of the rewrite and are
//! fail-closed at the seams that matter: an unknown placeholder on stdin is
//! never substituted, so the tool receives no secret.
//!
//! See `docs/architecture/secrets-interception.md`.

pub mod mcp;
pub mod raw;

/// Direction of a redact rewrite over a wrapped tool's stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Tool stdin: replace known placeholder tokens with their secret values.
    Rehydrate,
    /// Tool stdout: replace stored secret values with their placeholder tokens.
    Mask,
}
