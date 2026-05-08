import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import starlightBlog from 'starlight-blog';

const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const base = isGitHubPages ? '/firma-oss' : '/';

export default defineConfig({
  site: 'https://firma-ai.github.io',
  base,
  integrations: [
    mermaid({
      theme: 'neutral',
      autoTheme: true,
    }),
    starlight({
      title: 'OpenFirma',
      description: 'Governed runtime and local policy enforcement for AI agents.',
      customCss: ['./src/styles/fonts.css', './src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/firma-ai/firma-oss/edit/main/docs-site/',
      },
      lastUpdated: true,
      pagefind: true,
      expressiveCode: {
        themes: ['github-dark-default', 'github-light'],
        styleOverrides: {
          borderRadius: '0.5rem',
          codeFontFamily: '"JetBrains Mono Variable", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
          codeFontSize: '0.85rem',
        },
      },
      plugins: [
        starlightBlog({
          title: 'Blog',
          authors: {
            firma: {
              name: 'OpenFirma Team',
              url: 'https://github.com/firma-ai',
            },
          },
        }),
      ],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/firma-ai/firma-oss',
        },
      ],
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { label: 'Overview', slug: 'index' },
            { label: 'Quickstart', slug: 'quickstart' },
          ],
        },
        {
          label: 'Rust API Reference',
          collapsed: true,
          items: [
            { autogenerate: { directory: 'api', collapsed: true } },
          ],
        },
      ],
    }),
  ],
});
