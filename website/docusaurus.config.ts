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
  staticDirectories: ['static', '../docs/ux', '../docs/social'],

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
            {label: 'Resources (downloads)', to: '/resources'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/zyvorai/zyvor-netra'},
            {
              label: 'Changelog',
              href: 'https://github.com/zyvorai/zyvor-netra/blob/main/CHANGELOG.md',
            },
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
