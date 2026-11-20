import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'Netra',
  tagline: 'See the network. Diagnose it. Contain it.',
  favicon: 'img/favicon.svg',

  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  url: 'https://zyvorai.github.io',
  baseUrl: '/zyvor-netra/',

  organizationName: 'zyvorai',
  projectName: 'zyvor-netra',

  onBrokenLinks: 'throw',

  markdown: {
    // The repo docs are written for GitHub (CommonMark): `.md` stays plain
    // markdown so literals like <node-ip> are not parsed as JSX.
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  // Serve the repo's existing screenshot/social assets in place instead of
  // duplicating dozens of PNGs/GIFs into website/static — see docs/README.md
  // and the docs overhaul plan for why (single physical copy of each image,
  // referenced by both README and this site).
  headTags: [
    {
      tagName: 'script',
      attributes: {type: 'application/ld+json'},
      innerHTML: JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: 'Netra',
        applicationCategory: 'DeveloperApplication',
        operatingSystem: 'Linux, Kubernetes',
        description:
          'Standalone eBPF network observability and emergency network control for Linux and Kubernetes.',
        url: 'https://zyvorai.github.io/zyvor-netra/',
        codeRepository: 'https://github.com/zyvorai/zyvor-netra',
      }),
    },
  ],

  staticDirectories: ['static', '../docs/ux', '../docs/social'],

  themes: [
    [
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        indexDocs: true,
        indexPages: false,
        docsRouteBasePath: '/docs',
        language: ['en'],
      },
    ],
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/zyvorai/zyvor-netra/tree/main/website/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'netra-hero-dark.jpg',
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: 'Netra',
      logo: {
        alt: 'Netra',
        src: 'img/favicon.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/docs/integrations/mcp-integration',
          label: 'MCP',
          position: 'left',
        },
        {to: '/gallery', label: 'Gallery', position: 'left'},
        {
          to: '/resources',
          label: 'Resources',
          position: 'left',
        },
        {
          href: 'https://github.com/zyvorai/zyvor-netra',
          label: 'GitHub',
          position: 'right',
        },
        {
          href: 'https://zyvor.dev',
          label: 'Enterprise',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Quickstart', to: '/docs/getting-started/quickstart'},
            {label: 'Architecture', to: '/docs/core-concepts/architecture'},
            {label: 'Security', to: '/docs/security'},
            {label: 'MCP tool catalog', to: '/docs/reference/mcp-tools'},
            {label: 'Resources (downloads)', to: '/resources'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/zyvorai/zyvor-netra'},
            {label: 'Changelog', to: '/docs/reference/changelog'},
            {
              label: 'License',
              href: 'https://github.com/zyvorai/zyvor-netra/blob/main/LICENSE',
            },
          ],
        },
        {
          title: 'Zyvor Enterprise',
          items: [
            {label: 'zyvor.dev', href: 'https://zyvor.dev'},
            {label: 'sales@zyvor.dev', href: 'mailto:sales@zyvor.dev'},
            {
              label: 'Product Perspective (PDF)',
              href: 'pathname:///sales/Zyvor-Netra-Product-Perspective.pdf',
            },
            {
              label: 'Product Brochure (PDF)',
              href: 'pathname:///sales/Zyvor-Netra-Product-Brochure.pdf',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Zyvor. Zyvor Production License v1.0.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
