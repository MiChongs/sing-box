// UI chrome strings for both locales. Page bodies live in
// src/content/docs/<lang>/; the landing page copy lives in landing.ts.
import type { Lang } from '../data/nav';

export const ui = {
  zh: {
    htmlLang: 'zh-CN',
    siteName: 'sing-box Smart',
    siteDesc: 'sing-box xiaobaf14g 分支 Smart 出站策略组文档：按目标学习节点表现，自动选出当下最合适的节点。',
    footerNote: 'xiaobaf14g 分支 · 基于 reF1nd/sing-box',
    nav: { docs: '文档', config: '配置', api: 'Clash API', examples: '示例' },
    menu: '目录',
    closeMenu: '关闭目录',
    onThisPage: '本页内容',
    prev: '上一页',
    next: '下一页',
    editPage: '在 GitHub 上编辑此页',
    switchLang: 'Switch to English',
    langShort: 'EN',
    themeToggle: '切换深色 / 浅色',
    copy: '复制',
    copied: '已复制',
    copyFailed: '复制失败',
    skip: '跳到正文',
  },
  en: {
    htmlLang: 'en',
    siteName: 'sing-box Smart',
    siteDesc: 'Docs for the Smart outbound group in the sing-box xiaobaf14g fork: learns how each node performs per destination and picks the best one for every connection.',
    footerNote: 'xiaobaf14g fork · built on reF1nd/sing-box',
    nav: { docs: 'Docs', config: 'Config', api: 'Clash API', examples: 'Examples' },
    menu: 'Menu',
    closeMenu: 'Close menu',
    onThisPage: 'On this page',
    prev: 'Previous',
    next: 'Next',
    editPage: 'Edit this page on GitHub',
    switchLang: '切换到中文',
    langShort: '中',
    themeToggle: 'Toggle dark / light',
    copy: 'Copy',
    copied: 'Copied',
    copyFailed: 'Failed',
    skip: 'Skip to content',
  },
} as const satisfies Record<Lang, unknown>;

export const langs: Lang[] = ['zh', 'en'];

export function href(lang: Lang, slug = ''): string {
  const base = import.meta.env.BASE_URL.replace(/\/$/, '');
  return slug ? `${base}/${lang}/${slug}/` : `${base}/${lang}/`;
}
