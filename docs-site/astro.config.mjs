// @ts-check
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import mdx from '@astrojs/mdx';
// sitemap plugin crashes on an empty route set in 4.16 — punt to v0.2.

// GitHub Pages project-path deployment:
//   live URL = https://michongs.github.io/sing-box/
// Static links must all go through this base so CSS / fonts / assets
// resolve under the /sing-box/ prefix.
export default defineConfig({
  site: 'https://michongs.github.io',
  base: '/sing-box',
  trailingSlash: 'always',
  integrations: [
    tailwind({ applyBaseStyles: false }),
    mdx(),
  ],
  build: {
    format: 'directory',
  },
  markdown: {
    shikiConfig: {
      theme: 'github-light',
      wrap: true,
    },
  },
});
