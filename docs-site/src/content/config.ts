import { defineCollection, z } from 'astro:content';

// One entry per page per locale: src/content/docs/<lang>/<slug>.mdx.
// The sidebar order lives in src/data/nav.ts, not in frontmatter, so both
// locales always share the same structure.
const docs = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
  }),
});

export const collections = { docs };
