// Sidebar structure shared by both locales. Each slug must exist as
// src/content/docs/<lang>/<slug>.mdx in every locale; the page titles
// come from the entries' frontmatter.

export type Lang = 'zh' | 'en';

export interface NavSection {
  zh: string;
  en: string;
  slugs: string[];
}

export const sidebar: NavSection[] = [
  { zh: '入门', en: 'Getting started', slugs: ['quick-start', 'how-it-works'] },
  {
    zh: '指南',
    en: 'Guides',
    slugs: ['algorithms', 'smart-loadbalance', 'priority-and-pinning', 'health', 'lightgbm', 'asn-geox', 'storage-performance', 'examples'],
  },
  { zh: '参考', en: 'Reference', slugs: ['config', 'glossary', 'clash-api', 'troubleshooting', 'changelog'] },
];

export const orderedSlugs = sidebar.flatMap((s) => s.slugs);
