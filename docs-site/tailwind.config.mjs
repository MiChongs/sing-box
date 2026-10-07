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
      fontFamily: {
        serif: ['"Anthropic Serif"', 'Georgia', '"Noto Serif SC"', '"Source Han Serif SC"', '"Songti SC"', 'serif'],
        sans: ['"Anthropic Sans"', 'Inter', 'system-ui', '-apple-system', '"PingFang SC"', '"Microsoft YaHei"', '"Noto Sans SC"', 'sans-serif'],
        mono: ['"Anthropic Mono"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
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
        prose: '72ch',
        page: '88rem',
      },
    },
  },
  plugins: [],
};
