---
name: swamp
description: Build and operate Swamp models, workflows, data, vaults, extensions, and reports in OpenFirma.
---

# Swamp Skill

Use this skill for Swamp automation in this repository.

## Discovery

Search before building an integration:

1. Run `swamp extension search <query>` and prefer official `@swamp/*`
   extensions.
2. Run `swamp model type search <query>` for installed model types.
3. Inspect promising types with `swamp model type describe <type> --json`.
4. Pull an existing extension when it covers the domain. Extend a close model
   type before creating a custom model under `extensions/models/`.

Use `swamp help [<command>...]` for machine-readable CLI discovery rather than
guessing command syntax.

## Modeling

- Keep one model method focused on one purpose.
- Use model methods for external services instead of wrapping service CLIs in
  `command/shell`; reserve `command/shell` for one-off local commands.
- Persist reusable semantic state as typed, versioned model data.
- Mark credentials as sensitive and resolve them through `vault.get(...)`.
- Pin every `npm:` import version. Extension dependencies are bundled and are
  not tracked by the repository lockfiles.
- Prefer one fan-out method over concurrent calls to the same model, which
  contend on Swamp's per-model lock.

## Workflows

Treat requests to create or run a workflow as Swamp workflow requests unless
the user explicitly names another orchestration system. Workflows are YAML DAGs
of model-method and workflow steps; keep data-dependent sequential loops inside
a model method.

Wire steps with CEL and prefer
`data.latest("<model>", "<dataName>").attributes.<field>` over deprecated
`model.<name>.resource...` references.

## Safety And Failures

- Before destructive methods, run `swamp model get <name> --json` and verify
  resource identifiers.
- Query Swamp data with `swamp data query`; do not inspect `.swamp/` internals.
- After a failed model method or workflow, inspect its generated summary report
  before retrying. Confirm current report syntax with `swamp help report get`.

## Verification

Use the narrowest applicable checks while iterating, then run:

```bash
swamp doctor extensions
swamp workflow validate
swamp doctor workflows
swamp doctor secrets
```

For a publishable extension, also run formatting, quality checks, and
`swamp extension push <manifest> --dry-run`.
