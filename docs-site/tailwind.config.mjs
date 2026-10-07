/** @type {import('tailwindcss').Config} */
//
// Every color is a semantic token backed by a CSS variable (see
// src/styles/global.css). Light values keep the original parchment /
// terracotta palette; dark values are redefined under html.dark, so
// components never branch on the theme themselves.

const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./src/**/*.{astro,html,md,mdx,ts,tsx,js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bg: token('bg'),
        surface: token('surface'),
        'surface-2': token('surface-2'),
        line: token('line'),
        'line-soft': token('line-soft'),
        fg: token('fg'),
        'fg-2': token('fg-2'),
        muted: token('muted'),
        subtle: token('subtle'),
        accent: token('accent'),
        'accent-fill': token('accent-fill'),
        'accent-soft': token('accent-soft'),
        'on-accent': token('on-accent'),
        danger: token('danger'),
        'danger-soft': token('danger-soft'),
        ok: token('ok'),
        'ok-soft': token('ok-soft'),
        info: token('info'),
        'info-soft': token('info-soft'),
        focus: token('focus'),
      },
      // Latin and digits come from the self-hosted Inter / JetBrains Mono
      // (bundled by Astro, no third-party CDN). Chinese falls through to
      // the best CJK face the platform ships: a self-hosted CJK webfont
      // would add tens of megabytes. Headings use the same sans family as
      // the body (`display`), so Chinese and Latin in one heading match.
      fontFamily: {
        sans: [
          '"Inter Variable"', 'Inter',
          '"PingFang SC"', '"HarmonyOS Sans SC"', 'MiSans', '"Hiragino Sans GB"',
          '"Microsoft YaHei UI"', '"Microsoft YaHei"',
          '"Noto Sans CJK SC"', '"Noto Sans SC"', '"Source Han Sans SC"', '"WenQuanYi Micro Hei"',
          'system-ui', '-apple-system', '"Segoe UI"', 'Roboto', 'sans-serif',
        ],
        display: [
          '"Inter Variable"', 'Inter',
          '"PingFang SC"', '"HarmonyOS Sans SC"', 'MiSans', '"Hiragino Sans GB"',
          '"Microsoft YaHei UI"', '"Microsoft YaHei"',
          '"Noto Sans CJK SC"', '"Noto Sans SC"', '"Source Han Sans SC"', '"WenQuanYi Micro Hei"',
          'system-ui', '-apple-system', '"Segoe UI"', 'Roboto', 'sans-serif',
        ],
        mono: [
          '"JetBrains Mono Variable"', '"JetBrains Mono"',
          'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', '"Liberation Mono"',
          '"PingFang SC"', '"Microsoft YaHei UI"', '"Microsoft YaHei"', '"Noto Sans CJK SC"', '"Noto Sans SC"',
          'monospace',
        ],
      },
      boxShadow: {
        ring: 'var(--sh-ring)',
        'ring-2': 'var(--sh-ring-2)',
        lift: 'var(--sh-lift)',
      },
      borderRadius: {
        card: '12px',
      },
      maxWidth: {
        // In rem rather than ch: ch follows the font's digit width, and
        // ~40 Han characters / ~80 Latin characters per line read best.
        prose: '41rem',
        page: '88rem',
      },
    },
  },
  plugins: [],
};
