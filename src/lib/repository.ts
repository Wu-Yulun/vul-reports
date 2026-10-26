/**
 * Links back to the report source on GitHub.
 *
 * The repository is a constant: the site is served from its own domain now, so
 * there is nothing in the URL left to infer it from. `PUBLIC_REPOSITORY`
 * overrides it for a fork or a mirror.
 */
const DEFAULT_REPOSITORY = 'https://github.com/Wu-Yulun/vul-reports';

function resolveRepository(): string {
  const override = import.meta.env.PUBLIC_REPOSITORY;
  return (override || DEFAULT_REPOSITORY).replace(/\/$/, '');
}

export const REPOSITORY_URL = resolveRepository();

/** The branch the sources are linked on; this repository's default is `master`. */
export const SOURCE_BRANCH = 'master';

/** URL of a source file, e.g. `20261024/free-fs/readme.md`. */
export function sourceUrlOf(sourcePath: string): string {
  return `${REPOSITORY_URL}/blob/${SOURCE_BRANCH}/${sourcePath}`;
}
