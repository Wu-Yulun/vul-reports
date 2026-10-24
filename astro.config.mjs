// @ts-check
import { defineConfig } from 'astro/config';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./', import.meta.url));

export default defineConfig({
  site: 'https://wu-yulun.github.io',
  base: '/vul-reports',
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
