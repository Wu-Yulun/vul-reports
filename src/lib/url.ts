/**
 * Base path handling for sub-path hosting (`https://user.github.io/vul-reports/`).
 * Astro rewrites asset URLs itself; this helper is for links we write by hand.
 */
export function withBase(path: string): string {
  const base = import.meta.env.BASE_URL.replace(/\/$/, '');
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalized}`;
}

const origin = import.meta.env.SITE.replace(/\/$/, '');

/** Absolute URL of an app-relative path, e.g. `/20261024/free-fs/`. */
export function absoluteUrl(path: string): string {
  return `${origin}${withBase(path)}`;
}

/** Absolute URL of a path that already carries the base, e.g. `alternate.href`. */
export function absoluteFromHref(href: string): string {
  return `${origin}${href}`;
}
