---
name: rust-docs-guidelines
description: Guidelines for writing Rust documentation in OpenFirma.
---

# Rust Docs Guidelines

Standards to follow when writing Rust documentation.

## Guidelines

- Explain each key concept once, then link back to that canonical explanation.
- Use intra-doc links when mentioning Rust symbols.
- Focus on why, invariants, and usage constraints rather than line-by-line implementation.
- Avoid comments that merely restate what the code obviously does.
- Refer to constants and types by name instead of hard-coding duplicated values into docs.
- Use doc comments to explain contracts and safety-adjacent assumptions even though `unsafe` is forbidden in this repo.
