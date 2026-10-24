/**
 * Base path handling for sub-path hosting (`https://user.github.io/vul-reports/`).
 * Astro rewrites asset URLs itself; this helper is for links we write by hand.
 */
export function withBase(path: string): string {
  const base = import.meta.env.BASE_URL.replace(/\/$/, '');
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalized}`;
}
