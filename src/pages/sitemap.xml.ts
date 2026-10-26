import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { absoluteUrl } from '../lib/url';
import { isoDate } from '../lib/seo';

export const prerender = true;

/** Report id without its locale prefix: `zh-CN/20261024/free-fs` -> `20261024/free-fs`. */
function baseId(id: string): string {
  return id.replace(/^zh-CN\//, '');
}

function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

interface Entry {
  path: string;
  lastmod?: string;
  /** App-relative paths of the same page in other languages. */
  english?: string;
  chinese?: string;
}

function render(entry: Entry): string {
  const loc = absoluteUrl(entry.path);
  const alternates = [
    entry.english ? `<xhtml:link rel="alternate" hreflang="en" href="${escapeXml(absoluteUrl(entry.english))}" />` : '',
    entry.chinese ? `<xhtml:link rel="alternate" hreflang="zh-CN" href="${escapeXml(absoluteUrl(entry.chinese))}" />` : '',
    `<xhtml:link rel="alternate" hreflang="x-default" href="${escapeXml(absoluteUrl(entry.english ?? entry.chinese ?? entry.path))}" />`,
  ]
    .filter(Boolean)
    .join('\n    ');

  return [
    '  <url>',
    `    <loc>${escapeXml(loc)}</loc>`,
    entry.lastmod ? `    <lastmod>${entry.lastmod}</lastmod>` : '',
    `    ${alternates}`,
    '  </url>',
  ]
    .filter(Boolean)
    .join('\n');
}

export const GET: APIRoute = async () => {
  const reports = await getCollection('docs');
  const ids = new Set(reports.map((entry) => entry.id));
  const newest = reports.map((entry) => entry.data.date).sort().at(-1);

  const entries: Entry[] = [
    { path: '/', lastmod: newest ? isoDate(newest) : undefined, english: '/', chinese: '/zh-CN/' },
    { path: '/zh-CN/', lastmod: newest ? isoDate(newest) : undefined, english: '/', chinese: '/zh-CN/' },
  ];

  for (const entry of reports) {
    const base = baseId(entry.id);
    const english = `/${base}/`;
    const chinese = `/zh-CN/${base}/`;
    entries.push({
      path: `/${entry.id}/`,
      lastmod: isoDate(entry.data.date),
      english: ids.has(base) ? english : undefined,
      chinese: ids.has(`zh-CN/${base}`) ? chinese : undefined,
    });
  }

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    ...entries.map(render),
    '</urlset>',
    '',
  ].join('\n');

  return new Response(xml, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
