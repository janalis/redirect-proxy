import { execFileSync } from 'node:child_process'
import { defineConfig } from 'vitepress'

const repo = 'https://github.com/janalis/redirect-proxy'
const base = '/redirect-proxy/'
const site = 'https://janalis.github.io' + base

// Latest release tag, shown in the nav ("dev" outside a git checkout).
function version(): string {
  try {
    return execFileSync('git', ['describe', '--tags', '--abbrev=0'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()
  } catch {
    return 'dev'
  }
}

export default defineConfig({
  title: 'redirect-proxy',
  description: 'Fast HTTP redirect server with a web administration, a REST API and plain files.',
  lang: 'en-US',
  base,
  cleanUrls: true,
  lastUpdated: true,
  // docs/screenshots/ holds the fixture the screenshots are taken from.
  srcExclude: ['screenshots/**', 'scripts/**'],
  sitemap: { hostname: site },
  // Links to http://localhost:8081 point at the reader's own server.
  ignoreDeadLinks: 'localhostLinks',
  head: [
    ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: base + 'favicon-32.png' }],
    ['link', { rel: 'apple-touch-icon', href: base + 'apple-touch-icon.png' }],
    ['meta', { name: 'theme-color', content: '#3B2FA8' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'redirect-proxy' }],
    ['meta', { property: 'og:image', content: site + 'og.jpg' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
  ],
  themeConfig: {
    logo: { src: '/logo.png', alt: 'redirect-proxy' },
    nav: [
      { text: 'Guide', link: '/guide/introduction', activeMatch: '/guide/' },
      { text: 'REST API', link: '/guide/api' },
      { text: 'Contributing', link: '/contributing/', activeMatch: '/contributing/' },
      {
        text: version(),
        items: [
          { text: 'Changelog', link: '/changelog' },
          { text: 'Releases', link: repo + '/releases' },
        ],
      },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is redirect-proxy?', link: '/guide/introduction' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Getting started', link: '/guide/getting-started' },
          ],
        },
        {
          text: 'Usage',
          items: [
            { text: 'Redirection rules', link: '/guide/rules' },
            { text: 'Migrating from nginx or Apache', link: '/guide/migration' },
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Administration', link: '/guide/administration' },
            { text: 'Authentication', link: '/guide/authentication' },
            { text: 'REST API', link: '/guide/api' },
            { text: 'Command line', link: '/guide/cli' },
          ],
        },
        {
          text: 'Running it',
          items: [
            { text: 'Operations', link: '/guide/operations' },
            { text: 'Monitoring', link: '/guide/monitoring' },
            { text: 'Deployment', link: '/guide/deployment' },
            { text: 'Web servers', link: '/guide/web-servers' },
            { text: 'Access logs', link: '/guide/access-logs' },
            { text: 'Performance', link: '/guide/performance' },
          ],
        },
      ],
      '/contributing/': [
        {
          text: 'Contributing',
          items: [
            { text: 'Development', link: '/contributing/' },
            { text: 'Releasing', link: '/contributing/releasing' },
          ],
        },
      ],
    },
    search: { provider: 'local' },
    editLink: {
      pattern: repo + '/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
    socialLinks: [{ icon: 'github', link: repo }],
    outline: { level: [2, 3] },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'The admin bundles Bootstrap (MIT).',
    },
  },
})
