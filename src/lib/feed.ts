import { getCollection } from 'astro:content';
import type { Locale } from './locales';
import { describeReport, isoDate, siteName } from './seo';
import { absoluteUrl } from './url';

function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** RFC 822, the format RSS 2.0 wants for dates. */
function rfc822(date: string): string {
  return new Date(`${isoDate(date)}T00:00:00Z`).toUTCString();
}

const FEED_PATH = (locale: Locale) => (locale === 'zh-CN' ? '/zh-CN/rss.xml' : '/rss.xml');

/**
 * An RSS 2.0 feed of one language's reports, newest first. Reads the same
 * collection and the same summary extraction as the pages, so the feed cannot
 * drift from the site.
 */
export async function buildFeed(locale: Locale): Promise<string> {
  const reports = (await getCollection('docs'))
    .filter((entry) => entry.data.locale === locale)
    .sort((a, b) => b.data.date.localeCompare(a.data.date) || a.data.title.localeCompare(b.data.title));

  const home = absoluteUrl(locale === 'zh-CN' ? '/zh-CN/' : '/');
  const self = absoluteUrl(FEED_PATH(locale));
  const description =
    locale === 'zh-CN'
      ? '按日期倒序排列的漏洞报告，每份包含漏洞成因、复现环境搭建与复现过程。'
      : 'Vulnerability reports, newest first. Each one covers the root cause, a reproducible environment and the reproduction steps.';

  const items = reports.map((entry) => {
    const link = absoluteUrl(`/${entry.id}/`);
    const summary = describeReport({
      body: entry.data.body,
      title: entry.data.title,
      locale,
      date: entry.data.date,
    });

    return [
      '    <item>',
      `      <title>${escapeXml(entry.data.title)}</title>`,
      `      <link>${escapeXml(link)}</link>`,
      `      <guid isPermaLink="true">${escapeXml(link)}</guid>`,
      `      <pubDate>${rfc822(entry.data.date)}</pubDate>`,
      `      <description>${escapeXml(summary)}</description>`,
      '    </item>',
    ].join('\n');
  });

  const lastBuild = reports.length ? rfc822(reports[0].data.date) : new Date(0).toUTCString();

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">',
    '  <channel>',
    `    <title>${escapeXml(siteName(locale))}</title>`,
    `    <link>${escapeXml(home)}</link>`,
    `    <description>${escapeXml(description)}</description>`,
    `    <language>${locale === 'zh-CN' ? 'zh-CN' : 'en'}</language>`,
    `    <lastBuildDate>${lastBuild}</lastBuildDate>`,
    `    <atom:link href="${escapeXml(self)}" rel="self" type="application/rss+xml" />`,
    ...items,
    '  </channel>',
    '</rss>',
    '',
  ].join('\n');
}

export { FEED_PATH };
