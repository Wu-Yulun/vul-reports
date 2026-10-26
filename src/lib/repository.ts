/**
 * Links back to the report source on GitHub.
 *
 * The repository is taken from the site's own URL (`https://<user>.github.io/<repo>`
 * for GitHub Pages), so no extra configuration is needed; it can be overridden
 * with `PUBLIC_REPOSITORY` when the site is hosted elsewhere.
 */
function resolveRepository(): string {
  const override = import.meta.env.PUBLIC_REPOSITORY;
  if (override) return override.replace(/\/$/, '');

  const site = import.meta.env.SITE;
  const match = site?.match(/^https:\/\/([^./]+)\.github\.io/);
  if (!match) return '';

  const base = import.meta.env.BASE_URL.replace(/^\/|\/$/g, '');
  return `https://github.com/${match[1]}/${base}`;
}

export const REPOSITORY_URL = resolveRepository();

/** The branch the sources are linked on; this repository's default is `master`. */
export const SOURCE_BRANCH = 'master';

/** URL of a source file, e.g. `20261024/free-fs/readme.md`. */
export function sourceUrlOf(sourcePath: string): string {
  return `${REPOSITORY_URL}/blob/${SOURCE_BRANCH}/${sourcePath}`;
}
