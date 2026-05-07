import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const apiDir = path.resolve(process.argv[2] ?? 'dist/api');

const escapeHtml = (value) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const crateTitle = async (dirName) => {
  const indexPath = path.join(apiDir, dirName, 'index.html');
  const html = await readFile(indexPath, 'utf8');
  const title = html.match(/<title>([^<]+)<\/title>/u)?.[1] ?? dirName;
  return title.replace(/\s+-\s+Rust$/u, '');
};

const entries = await readdir(apiDir, { withFileTypes: true });
const crates = (
  await Promise.all(
    entries
      .filter((entry) => entry.isDirectory())
      .filter((entry) => entry.name.startsWith('firma'))
      .map(async (entry) => ({
        name: await crateTitle(entry.name),
        href: `${entry.name}/`,
      })),
  )
).sort((left, right) => left.name.localeCompare(right.name));

const links = crates
  .map(
    (crate) => `
      <li>
        <a href="${escapeHtml(crate.href)}">${escapeHtml(crate.name)}</a>
      </li>`,
  )
  .join('');

await writeFile(
  path.join(apiDir, 'index.html'),
  `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OpenFirma Rust API Reference</title>
    <style>
      :root {
        color-scheme: light dark;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: Canvas;
        color: CanvasText;
      }
      body {
        margin: 0;
      }
      main {
        width: min(64rem, calc(100% - 2rem));
        margin: 0 auto;
        padding: 4rem 0;
      }
      a {
        color: #2563eb;
        font-weight: 650;
        text-decoration: none;
      }
      a:hover {
        text-decoration: underline;
      }
      ul {
        display: grid;
        gap: 0.75rem;
        grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
        list-style: none;
        padding: 0;
      }
      li {
        border: 1px solid color-mix(in srgb, CanvasText 16%, transparent);
        border-radius: 0.75rem;
        padding: 1rem;
      }
    </style>
  </head>
  <body>
    <main>
      <p><a href="../">Back to OpenFirma docs</a></p>
      <h1>OpenFirma Rust API Reference</h1>
      <p>Generated from the workspace crates with <code>cargo doc --workspace --no-deps</code>.</p>
      <ul>${links}
      </ul>
    </main>
  </body>
</html>
`,
);
