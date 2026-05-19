import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import starlightBlog from 'starlight-blog';
const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const base = isGitHubPages ? '/openfirma' : '/';
export default defineConfig({
  site: 'https://firma-ai.github.io',
  base,
  vite: {
    optimizeDeps: {
      exclude: ['starlight-blog'],
    },
  },
  integrations: [
    mermaid({
      theme: 'neutral',
      autoTheme: true,
    }),
    starlight({
      title: 'OpenFirma',
      description: 'Governed runtime and local policy enforcement for AI agents.',
      logo: {
        src: './src/assets/openfirma-logo.png',
        replacesTitle: true,
        alt: 'OpenFirma',
      },
      customCss: ['./src/styles/fonts.css', './src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/firma-ai/openfirma/edit/main/docs-site/',
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
          href: 'https://github.com/firma-ai/openfirma',
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
          label: 'Concepts',
          items: [
            { label: 'Architecture & invariants', slug: 'concepts/architecture' },
            { label: 'The enforcement pipeline', slug: 'concepts/pipeline' },
            { label: 'Action classes', slug: 'concepts/action-classes' },
            { label: 'Capabilities', slug: 'concepts/capabilities' },
            { label: 'Policies', slug: 'concepts/policies' },
            { label: 'Interception', slug: 'concepts/interception' },
            { label: 'Connectors', slug: 'concepts/connectors' },
            { label: 'The sandbox boundary', slug: 'concepts/sandbox' },
            { label: 'Threat model & bypasses', slug: 'concepts/threat-model' },
          ],
        },
        {
          label: 'User Guides',
          items: [
            { label: 'Run the sidecar standalone', slug: 'guides/run-the-sidecar' },
            { label: 'Manage the stack (firma stack & monitor)', slug: 'guides/manage-the-stack' },
            { label: 'Diagnose with firma doctor', slug: 'guides/firma-doctor' },
            { label: 'Write your first Cedar policy', slug: 'guides/write-a-cedar-policy' },
            { label: 'Issue capability tokens', slug: 'guides/issue-capability-tokens' },
            { label: 'Wrap an agent with firma run', slug: 'guides/firma-run' },
            { label: 'Enable HTTPS MITM', slug: 'guides/https-mitm' },
            { label: 'Extend the action-class mapping', slug: 'guides/extend-mapping' },
            { label: 'Inject credentials', slug: 'guides/inject-credentials' },
            { label: 'Read & verify the audit log', slug: 'guides/audit-log' },
            { label: 'Secure a local coding agent', slug: 'guides/secure-a-coding-agent' },
            { label: 'Deploy a GenAI web app', slug: 'guides/deploy-a-genai-webapp' },
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
