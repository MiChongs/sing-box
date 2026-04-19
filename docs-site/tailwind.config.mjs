/** @type {import('tailwindcss').Config} */
//
// Design tokens mirror C:\Users\YST\GolandProjects\sing-box\DESIGN.md
// (Anthropic Claude design system). Values are verbatim — do not "adjust"
// colors or line-heights without updating DESIGN.md first, or the
// parchment / terracotta / warm-neutral palette will drift out of sync
// with the stated brand intent.

export default {
  content: [
    './src/**/*.{astro,html,md,mdx,ts,tsx,js,jsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Surface / background
        parchment: '#f5f4ed',
        ivory:     '#faf9f5',
        'warm-sand': '#e8e6dc',
        'dark-surface': '#30302e',
        'deep-dark':    '#141413',

        // Brand
        terracotta: '#c96442',
        coral:      '#d97757',

        // Text neutrals — every gray has a yellow-brown undertone.
        ink:             '#141413',
        'charcoal-warm': '#4d4c48',
        'olive-gray':    '#5e5d59',
        'stone-gray':    '#87867f',
        'dark-warm':     '#3d3d3a',
        'warm-silver':   '#b0aea5',

        // Borders / rings
        'border-cream': '#f0eee6',
        'border-warm':  '#e8e6dc',
        'border-dark':  '#30302e',
        'ring-warm':    '#d1cfc5',
        'ring-deep':    '#c2c0b6',

        // Semantic
        'error-crimson': '#b53333',
        'focus-blue':    '#3898ec',
      },
      fontFamily: {
        // Anthropic* faces are commercial and NOT self-hosted. local() probe
        // lets Anthropic / Claude.ai visitors hit their on-device copies;
        // everyone else falls through to Georgia / Inter / JetBrains Mono.
        serif: ['"Anthropic Serif"', 'Georgia', '"Times New Roman"', 'serif'],
        sans:  ['"Anthropic Sans"', 'Inter', 'system-ui', 'sans-serif'],
        mono:  ['"Anthropic Mono"', '"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        // Serif headings — single 500 weight across sizes.
        'hero-64':    ['4rem',    { lineHeight: '1.10' }],
        'section-52': ['3.25rem', { lineHeight: '1.20' }],
        'sub-36':     ['2.3rem',  { lineHeight: '1.30' }],
        'card-32':    ['2rem',    { lineHeight: '1.10' }],
        'sub-25':     ['1.6rem',  { lineHeight: '1.20' }],
        'feat-20':    ['1.3rem',  { lineHeight: '1.20' }],

        // Sans / serif body.
        'lead-20':    ['1.25rem', { lineHeight: '1.60' }],
        'body-17':    ['1.06rem', { lineHeight: '1.60' }],
        'body-16':    ['1rem',    { lineHeight: '1.60' }],
        'small-15':   ['0.94rem', { lineHeight: '1.60' }],
        'caption-14': ['0.88rem', { lineHeight: '1.43' }],
        'label-12':   ['0.75rem', { lineHeight: '1.60', letterSpacing: '0.12px' }],
        'overline-10':['0.63rem', { lineHeight: '1.60', letterSpacing: '0.5px' }],

        // Code.
        'mono-15':    ['0.94rem', { lineHeight: '1.60', letterSpacing: '-0.32px' }],
      },
      boxShadow: {
        // Ring shadows create border-like depth without visible borders,
        // per DESIGN.md: "0px 0px 0px 1px" signature stroke.
        'ring-1': '0 0 0 1px rgb(20 20 19 / 0.08)',
        'ring-2': '0 0 0 1px rgb(20 20 19 / 0.12), 0 1px 2px rgb(20 20 19 / 0.04)',
        'ring-3': '0 0 0 1px rgb(20 20 19 / 0.14), 0 6px 24px -6px rgb(20 20 19 / 0.12)',
      },
      borderRadius: {
        'card': '12px',
      },
      maxWidth: {
        'prose': '68ch',
        'page':  '72rem',
      },
    },
  },
  plugins: [],
};
