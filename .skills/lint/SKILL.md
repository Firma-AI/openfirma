---
name: lint
description: Check formatting and lint rules for OpenFirma Rust, TOML, and Markdown changes.
---

# Lint Skill

Check formatting and lint rules before finishing a change.

## Usage

Run this skill after editing `.rs`, `.toml`, or `.md` files.

## Instructions

### 1. Format check

```bash
make fmt
```

This runs `dprint check` for Rust, TOML, and Markdown.

If formatting needs to be fixed, run:

```bash
dprint fmt
```

### 2. Lint check

```bash
make lint
```

### 3. Common repo-specific lint expectations

- Do not use `.unwrap()`.
- Do not use `.expect()`.
- Do not use `panic!()`.
- Do not use `unsafe`.
- Prefer `Result<T, E>` with `thiserror` for recoverable failures.

### 4. Focused lint run

For quicker iteration on one crate:

```bash
cargo clippy -p <crate-name> --all-features --all-targets
```

## Notes

- `docs-site/` uses its own toolchain; `dprint` does not format that subtree.
- If clippy and AGENTS guidance ever disagree, follow the stricter interpretation.
