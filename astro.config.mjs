// @ts-check
import { defineConfig } from 'astro/config';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./', import.meta.url));

export default defineConfig({
  site: 'https://vul.yulun.ac.cn',
  // Root hosting on Cloudflare Pages; `withBase` keeps links correct if the
  // site ever moves back under a sub-path.
  base: '/',
  server: { host: '0.0.0.0', port: 26262 },
  vite: {
    server: {
      host: '0.0.0.0',
      port: 26262,
      // Reports are read from the repository root, next to `src/`.
      fs: { allow: [root] },
    },
  },
  markdown: {
    shikiConfig: { themes: { light: 'one-light', dark: 'one-dark-pro' } },
  },
});
