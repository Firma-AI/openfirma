import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const base = isGitHubPages ? '/firma-oss' : '/';
const rustdocPath = isGitHubPages ? `${base}/api/` : '/api/';

export default defineConfig({
  site: 'https://firma-ai.github.io',
  base,
  integrations: [
    starlight({
      title: 'OpenFirma',
      description: 'Governed runtime and local policy enforcement for AI agents.',
      customCss: ['./src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/firma-ai/firma-oss/edit/main/docs-site/',
      },
      lastUpdated: true,
      pagefind: true,
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
          items: [{ label: 'Overview', slug: 'index' }],
        },
        {
          label: 'API Reference',
          items: [{ label: 'Rustdoc', link: rustdocPath }],
        },
      ],
    }),
  ],
});
