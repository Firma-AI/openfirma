---
bolt: 003-paseto-v4
created: 2026-03-28T11:10:00Z
status: accepted
superseded_by: null
---

# ADR-001: Use `pasetors` instead of `rusty_paseto` for PASETO v4

## Context

The tech stack (`memory-bank/standards/tech-stack.md`) specifies `rusty_paseto` as the PASETO v4 token validation crate. During construction of bolt 003-paseto-v4, we researched both `rusty_paseto` (0.9.0) and `pasetors` (0.7.8) to verify Ed25519 v4.public support before implementation.

The research revealed significant differences in maturity, safety, and dependency weight that favor `pasetors`. Since `firma-core` is a security-critical shared library with `deny(unsafe_code)`, the crate choice for cryptographic operations has outsized impact on the project's security posture.

## Decision

Use `pasetors` 0.7.8 instead of `rusty_paseto` 0.9.0 for PASETO v4.public token signing and verification. Update `tech-stack.md` to reflect this choice.

## Rationale

### Head-to-Head Comparison

| Factor | `rusty_paseto` 0.9.0 | `pasetors` 0.7.8 |
|--------|----------------------|-------------------|
| Total downloads | ~165K | ~6.5M (40x more) |
| Last updated | Dec 2025 | Feb 2026 |
| Unsafe code policy | Allowed | `#![forbid(unsafe_code)]` |
| Ed25519 backend | `ed25519-dalek` + `ring` (C/asm) | `ed25519-compact` (pure Rust) |
| Compile-time impact | Heavy (`ring` requires C compiler) | Light (pure Rust) |
| `no_std` support | No | Yes |
| API ergonomics | Type-driven generic builder/parser | Simple functions + `Claims` struct |
| Key interoperability | Standard Ed25519 byte layout | Standard Ed25519 byte layout |

### Why `pasetors` wins

1. **Safety alignment**: `forbid(unsafe_code)` matches `firma-core`'s `deny(unsafe_code)` policy. The entire PASETO stack is safe Rust.
2. **No `ring` dependency**: `ring` brings C/assembly code, complicating cross-compilation and auditing. `pasetors` uses `ed25519-compact`, which is pure Rust.
3. **Battle-tested**: 40x more downloads indicates significantly wider production usage and bug discovery.
4. **Simpler API**: `pasetors::public::sign()` / `pasetors::public::verify()` are straightforward function calls vs. `rusty_paseto`'s generic builder pattern with type-level version/purpose parameters.
5. **Active maintenance**: Updated more recently (Feb 2026 vs Dec 2025).

### Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| `rusty_paseto` 0.9.0 | Originally specified in tech stack; native `ed25519-dalek` types | Heavy `ring` dep; allows unsafe; 40x fewer downloads; more complex API | Safety and dependency concerns outweigh familiarity |
| Manual PASETO implementation | Full control; no external dependency | High effort; error-prone for crypto; maintenance burden | Never roll your own crypto |

## Consequences

### Positive

- Entire crypto path is safe Rust — no `unsafe` blocks anywhere in the dependency chain for PASETO operations
- Faster compilation — no C/assembly compilation step from `ring`
- Simpler cross-compilation for release binaries (no C toolchain required)
- Cleaner, more readable PASETO code

### Negative

- Deviation from documented tech stack (requires `tech-stack.md` update)
- `ed25519-compact` is less widely used than `ed25519-dalek` — though `pasetors` itself has 6.5M downloads

### Risks

- `ed25519-compact` has a smaller auditing footprint than `ed25519-dalek`. Mitigation: `pasetors` with `ed25519-compact` has 6.5M downloads — extensive real-world validation.
- If a future crate requires `ed25519-dalek` key types directly, conversion is needed. Mitigation: Both use standard Ed25519 byte layout — conversion is trivial (same bytes, different type wrappers).

## Related

- **Stories**: 001-paseto-signer, 002-paseto-verifier, 003-token-round-trip-tests
- **Standards**: `tech-stack.md` must be updated (replace `rusty_paseto` with `pasetors`)
- **Previous ADRs**: None
