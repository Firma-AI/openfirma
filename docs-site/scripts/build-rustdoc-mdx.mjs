#!/usr/bin/env node

/**
 * Bridge between cargo-doc-md (markdown rustdoc) and Astro Starlight.
 *
 * Pipeline:
 *   1. Run `cargo doc-md --workspace --no-deps -o target/doc-md` from the repo root.
 *   2. Walk the generated tree and, for every `*.md`, prepend Starlight
 *      frontmatter + sanitize cargo-doc-md quirks (rust-path link URLs,
 *      breadcrumb prefix, etc.).
 *   3. Write the result into `docs-site/src/content/docs/api/`, where
 *      Starlight's content collection picks it up via the `autogenerate`
 *      sidebar entry configured in `astro.config.mjs`.
 *
 * The output directory is treated as build output (gitignored). Re-running
 * this script always produces a clean tree.
 */

import { spawn } from 'node:child_process';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const docsSite = path.resolve(here, '..');
const repoRoot = path.resolve(docsSite, '..');
const docMdDir = path.join(repoRoot, 'target', 'doc-md');
const outDir = path.join(docsSite, 'src', 'content', 'docs', 'api');

const SKIP_CARGO = process.env.SKIP_CARGO_DOC_MD === '1';

const ROOT_INDEX_TITLE = 'Rust API Reference';
const ROOT_INDEX_DESCRIPTION =
  'Auto-generated reference for every public item in the OpenFirma workspace crates.';

// Map crate folder name (snake_case) to its sidebar label (kebab-case package name).
const CRATE_LABELS = {
  firma_authority: 'firma-authority',
  firma_core: 'firma-core',
  firma_demo_fixture: 'firma-demo-fixture',
  firma_demo_tui: 'firma-demo-tui',
  firma_grpc_interceptor_proto: 'firma-grpc-interceptor-proto',
  firma_run: 'firma-run',
  firma_sidecar: 'firma-sidecar',
};

function runCargoDocMd() {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'cargo',
      ['doc-md', '--workspace', '--no-deps', '-o', docMdDir],
      { cwd: repoRoot, stdio: 'inherit' },
    );
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`cargo doc-md exited with code ${code}`));
    });
    child.on('error', reject);
  });
}

/**
 * Build a frontmatter block. Values are JSON-encoded so we don't have to
 * worry about quoting/escaping of titles that may contain colons or quotes.
 */
function buildFrontmatter({ title, description, sidebarOrder, sidebarLabel }) {
  const lines = ['---'];
  lines.push(`title: ${JSON.stringify(title)}`);
  if (description) {
    lines.push(`description: ${JSON.stringify(description)}`);
  }
  if (sidebarLabel || sidebarOrder !== undefined) {
    lines.push('sidebar:');
    if (sidebarLabel) lines.push(`  label: ${JSON.stringify(sidebarLabel)}`);
    if (sidebarOrder !== undefined) lines.push(`  order: ${sidebarOrder}`);
  }
  lines.push('editUrl: false');
  lines.push('pagefind: true');
  lines.push('tableOfContents: false');
  lines.push('---', '');
  return lines.join('\n');
}

function starlightSlug(value) {
  return value
    .trim()
    .toLowerCase()
    .replace(/<[^>]*>/gu, '')
    .replace(/`/gu, '')
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s+/gu, '-');
}

function buildAnchorMap(content) {
  const anchors = new Map();
  for (const match of content.matchAll(/^#{1,6}\s+(.+?)\s*$/gmu)) {
    const heading = match[1].trim();
    const slug = starlightSlug(heading);
    if (!slug) continue;

    anchors.set(slug, slug);

    const moduleMatch = heading.match(/^Module:\s*(.+)$/u);
    if (moduleMatch) {
      const moduleName = moduleMatch[1].split('::').pop();
      const moduleAlias = moduleName ? starlightSlug(moduleName) : '';
      if (moduleAlias) anchors.set(moduleAlias, slug);
      continue;
    }

    const lastPathSegment = heading.includes('::') ? heading.split('::').pop() : '';
    const pathAlias = lastPathSegment ? starlightSlug(lastPathSegment) : '';
    if (pathAlias) anchors.set(pathAlias, slug);
  }
  return anchors;
}

/**
 * Derive a sensible title for a generated page.
 *
 *   - Workspace root index           -> "Rust API Reference"
 *   - <crate>/index.md               -> kebab-case crate name (e.g. "firma-sidecar")
 *   - <crate>/<crate>.md             -> "<crate> (root module)"
 *   - <crate>/<...>/<name>.md        -> "<name>"
 */
function deriveTitle(relPath, raw) {
  const parts = relPath.split(path.sep);

  if (parts.length === 1 && parts[0] === 'index.md') {
    return ROOT_INDEX_TITLE;
  }

  const crate = parts[0];
  const filename = parts[parts.length - 1];

  if (filename === 'index.md') {
    return CRATE_LABELS[crate] ?? crate;
  }

  const stem = filename.replace(/\.md$/u, '');

  if (parts.length === 2 && stem === crate) {
    return `${CRATE_LABELS[crate] ?? crate} (root module)`;
  }

  // Prefer the first H1 from the body if present (cargo-doc-md emits
  // "# Module: foo::bar"); otherwise fall back to the file stem.
  const h1 = raw.match(/^#\s+(?:Module:\s*)?(.+?)\s*$/mu);
  if (h1) {
    const value = h1[1].trim();
    // Show only the leaf segment to keep the sidebar tidy.
    const leaf = value.includes('::') ? value.split('::').pop() : value;
    return leaf || stem;
  }
  return stem;
}

/**
 * Strip cargo-doc-md output quirks that don't render well in Starlight:
 *   - Leading "**foo > bar**" breadcrumb (Starlight already renders one).
 *   - Markdown links whose URL contains rust path syntax (`::`,
 *     `Self::`, `crate::`, `super::`, `self::`) - these are unresolved
 *     intra-doc links. We strip the URL, keeping the link text inline.
 *   - Relative `*.md` links from cargo-doc-md. Astro/Starlight does not
 *     resolve these inside generated content, so we rewrite them to the
 *     routed Starlight shape (`foo.md` -> `foo/`, `foo/index.md` -> `foo/`).
 */
function resolveRelPath(fromRelPath, markdownPath) {
  const fromDir = path.posix.dirname(fromRelPath.split(path.sep).join('/'));
  return path.posix.normalize(path.posix.join(fromDir, markdownPath));
}

function rewriteMarkdownUrl(url, relPath, anchorMaps) {
  if (
    /^[a-z][a-z0-9+.-]*:/iu.test(url) ||
    url.startsWith('//')
  ) {
    return url;
  }

  const anchorIndex = url.indexOf('#');
  const pathname = anchorIndex === -1 ? url : url.slice(0, anchorIndex);
  const anchor = anchorIndex === -1 ? '' : url.slice(anchorIndex);
  let mappedAnchor = anchor;

  if (anchor) {
    const targetRelPath = pathname.endsWith('.md')
      ? resolveRelPath(relPath, pathname)
      : relPath.split(path.sep).join('/');
    const anchorMap = anchorMaps.get(targetRelPath);
    const alias = anchor.slice(1);
    mappedAnchor = anchorMap?.has(alias) ? `#${anchorMap.get(alias)}` : anchor;
  }

  if (!pathname.endsWith('.md')) {
    return `${pathname}${mappedAnchor}`;
  }

  const withoutExtension = pathname.slice(0, -'.md'.length);
  const routed = withoutExtension.endsWith('/index')
    ? withoutExtension.slice(0, -'index'.length)
    : `${withoutExtension}/`;

  return `${routed || './'}${mappedAnchor}`;
}

function sanitizeBody(content, relPath, anchorMaps) {
  let out = content;

  out = out.replace(/^\*\*[^*\n]+\*\*\s*\n+/u, '');

  out = out.replace(/\[([^\]]+)\]\(([^)\s]+)\)/gu, (match, text, url) => {
    if (
      url.includes('::') ||
      /^(Self|crate|super|self)\b/u.test(url) ||
      url.startsWith('$crate')
    ) {
      return text;
    }
    return `[${text}](${rewriteMarkdownUrl(url, relPath, anchorMaps)})`;
  });

  return out;
}

async function transformFile(srcPath, dstPath, relPath, anchorMaps) {
  const raw = await readFile(srcPath, 'utf8');
  const body = sanitizeBody(raw, relPath, anchorMaps);
  const parts = relPath.split(path.sep);
  const filename = parts[parts.length - 1];
  const isWorkspaceIndex = parts.length === 1 && filename === 'index.md';
  const isCrateIndex = parts.length === 2 && filename === 'index.md';
  const isCrateRoot =
    parts.length === 2 && filename === `${parts[0]}.md`;

  const title = deriveTitle(relPath, raw);

  // Sidebar ordering inside each crate folder:
  //   index.md        -> 0  (group landing)
  //   <crate>.md      -> 1  (root module page)
  //   everything else -> alpha (no explicit order)
  let sidebarOrder;
  let sidebarLabel;
  if (isWorkspaceIndex) {
    sidebarOrder = 0;
    sidebarLabel = ROOT_INDEX_TITLE;
  } else if (isCrateIndex) {
    sidebarOrder = 0;
    sidebarLabel = CRATE_LABELS[parts[0]] ?? parts[0];
  } else if (isCrateRoot) {
    sidebarOrder = 1;
    sidebarLabel = 'Crate root';
  }

  const frontmatter = buildFrontmatter({
    title,
    description: isWorkspaceIndex ? ROOT_INDEX_DESCRIPTION : undefined,
    sidebarOrder,
    sidebarLabel,
  });

  await writeFile(dstPath, frontmatter + body);
}

async function collectMarkdownFiles(srcDir, relBase = '') {
  const files = [];
  const entries = await readdir(srcDir, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(srcDir, entry.name);
    const relPath = relBase ? path.join(relBase, entry.name) : entry.name;
    if (entry.isDirectory()) {
      files.push(...(await collectMarkdownFiles(srcPath, relPath)));
    } else if (entry.name.endsWith('.md')) {
      files.push({ srcPath, relPath });
    }
  }
  return files;
}

async function buildAnchorMaps(files) {
  const anchorMaps = new Map();
  for (const file of files) {
    const raw = await readFile(file.srcPath, 'utf8');
    anchorMaps.set(file.relPath.split(path.sep).join('/'), buildAnchorMap(raw));
  }
  return anchorMaps;
}

async function writeTransformedFiles(files, anchorMaps) {
  for (const file of files) {
    const dstPath = path.join(outDir, file.relPath);
    await mkdir(path.dirname(dstPath), { recursive: true });
    await transformFile(file.srcPath, dstPath, file.relPath, anchorMaps);
  }
}

async function main() {
  if (!SKIP_CARGO) {
    console.log('[rustdoc-mdx] Running cargo doc-md ...');
    await runCargoDocMd();
  } else {
    console.log('[rustdoc-mdx] SKIP_CARGO_DOC_MD=1 - reusing existing target/doc-md');
  }

  console.log(`[rustdoc-mdx] Wiping ${outDir}`);
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  console.log(`[rustdoc-mdx] Transforming markdown -> ${outDir}`);
  const files = await collectMarkdownFiles(docMdDir);
  const anchorMaps = await buildAnchorMaps(files);
  await writeTransformedFiles(files, anchorMaps);

  console.log('[rustdoc-mdx] Done.');
}

main().catch((err) => {
  console.error('[rustdoc-mdx] FAILED:', err);
  process.exitCode = 1;
});
