# OpenFirma Docs Site

This directory contains the public documentation site for OpenFirma.

## Development

Dependencies are resolved from the public npm registry via the project-local `.npmrc`.

```bash
corepack pnpm install
corepack pnpm dev
```

From the repository root, use `just docs-dev` to build Rustdoc once, mount it at
`/api/`, and start Starlight with hot reload. Changes to prose docs reload
automatically; changes to Rust API docs need the command to be restarted.

## Production Build

Build only the Starlight prose site:

```bash
corepack pnpm build
```

Build the prose site and mount Rustdoc at `dist/api/`:

```bash
corepack pnpm build:with-rustdoc
```
