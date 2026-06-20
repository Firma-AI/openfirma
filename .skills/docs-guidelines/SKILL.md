---
name: docs-guidelines
description: General documentation guidelines for OpenFirma code, docs, and contributor-facing material.
---

# Documentation Guidelines

General guidelines for writing code comments, docstrings, README text, and docs-site pages.

## Guidelines

- Document the non-obvious parts of every new component.
- Prefer code-enforced invariants over prose when possible.
- State each fact in one canonical place and reference it elsewhere instead of repeating it.
- Focus on why, constraints, and invariants, not on obvious implementation mechanics.
- Keep docs concise, concrete, and task-oriented.
- Start from the user's task or question, not internal implementation order.
- Document sharp edges and operational gotchas when they affect real use.
- When major behavior, CLI, configuration, architecture, or public API changes, update `docs-site/` in the same change set.
- When discovery or integration guidance changes, update `docs-site/public/llms.txt` too.

## Placement model

Put each fact in the layer that owns it:

- Call sites: local intent, assumptions, or sequencing constraints.
- Definitions and interfaces: contract, inputs, outputs, errors, side effects, invariants.
- Implementations: non-obvious internal tradeoffs and workarounds.
- READMEs and docs pages: module or product-level context.
