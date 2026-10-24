import { getCollection } from 'astro:content';
import { withBase } from './url';

/**
 * The locale a report is written in, and the directory it lives in
 * (`<date>/<software>`), independent of the locale prefix in its slug.
 */
export const DEFAULT_LOCALE = 'en';

/** `zh-CN/20261024/free-fs` -> `20261024/free-fs`; `20261024/free-fs` is unchanged. */
export function reportDirOf(id: string): string {
  return id.replace(/^(zh-CN|en)\//, '');
}

/** Builds the slug of a report in another locale. */
export function localizedId(id: string, locale: string): string {
  const dir = reportDirOf(id);
  return locale === DEFAULT_LOCALE ? dir : `${locale}/${dir}`;
}

/**
 * Finds the same report in the other locale, so a page can link to its
 * translation. Returns `null` when the report exists in one language only.
 */
export async function getAlternate(
  id: string,
  currentLocale: string,
): Promise<{ locale: 'en' | 'zh-CN'; label: string; href: string } | null> {
  const target = currentLocale === 'zh-CN' ? 'en' : 'zh-CN';
  const targetId = localizedId(id, target);
  const reports = await getCollection('docs');
  if (!reports.some((entry) => entry.id === targetId)) return null;

  return {
    locale: target,
    label: target === 'en' ? 'English' : '中文',
    href: withBase(`/${targetId}/`),
  };
}
