// @ts-check
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import mdx from '@astrojs/mdx';

// Wrap every Markdown table in a scroll container so wide reference
// tables scroll on their own instead of widening the page on phones.
function rehypeWrapTables() {
  /** @param {any} node */
  const walk = (node) => {
    if (!Array.isArray(node.children)) return;
    node.children = node.children.map((/** @type {any} */ child) => {
      if (child.type === 'element' && child.tagName === 'table') {
        return {
          type: 'element',
          tagName: 'div',
          properties: { className: ['table-wrap', 'scroll-thin'] },
          children: [child],
        };
      }
      walk(child);
      return child;
    });
  };
  return (/** @type {any} */ tree) => walk(tree);
}

// GitHub Pages project-path deployment:
//   live URL = https://michongs.github.io/sing-box/
// Every internal link goes through import.meta.env.BASE_URL.
export default defineConfig({
  site: 'https://michongs.github.io',
  base: '/sing-box',
  trailingSlash: 'always',
  integrations: [tailwind({ applyBaseStyles: false }), mdx()],
  build: {
    format: 'directory',
  },
  // Pages renamed in the 2026-10 restructure; keep old links alive.
  redirects: {
    '/zh/watchdog': '/sing-box/zh/health/',
    '/en/watchdog': '/sing-box/en/health/',
  },
  markdown: {
    shikiConfig: {
      themes: { light: 'github-light', dark: 'github-dark' },
      wrap: false,
    },
    rehypePlugins: [rehypeWrapTables],
  },
});
