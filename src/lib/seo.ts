import type { Locale } from './locales';

/** `20261024` -> `2026-10-24`; passes through anything else. */
export function isoDate(date: string): string {
  const match = date.match(/^(\d{4})(\d{2})(\d{2})$/);
  return match ? `${match[1]}-${match[2]}-${match[3]}` : date;
}

export function siteName(locale: Locale): string {
  return locale === 'zh-CN' ? '漏洞报告' : 'Vulnerability Reports';
}

const METADATA =
  /^(软件名称|开发者或厂商|开发者|厂商|代码仓库|受影响版本|影响版本|前置条件|Software|Developer|Vendor|Repository|Affected versions|Prerequisites)\s*[:：]/i;
const SUMMARY = /^(简要描述|漏洞描述|Summary|Description)\s*[:：]\s*/i;

function stripMarkdown(text: string): string {
  return text
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit);
  const boundary = Math.max(cut.lastIndexOf('。'), cut.lastIndexOf('. '), cut.lastIndexOf('，'), cut.lastIndexOf(', '));
  return `${(boundary > limit * 0.5 ? cut.slice(0, boundary + 1) : cut).trim()}…`;
}

/**
 * A one- or two-sentence description for search engines and link previews.
 * Reads the report's own summary line when it has one, so nothing is invented
 * and the source file stays untouched.
 */
export function describeReport(input: {
  body: string;
  title: string;
  locale: Locale;
  date: string;
}): string {
  const { body, title, locale, date } = input;
  const lines = body.split('\n');
  const prose: string[] = [];
  let inFence = false;

  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('```')) {
      inFence = !inFence;
      continue;
    }
    if (inFence || !line) continue;
    if (line.startsWith('#') || line.startsWith('|') || line.startsWith('![')) continue;
    if (METADATA.test(line)) continue;

    const summary = line.match(SUMMARY);
    if (summary) return truncate(stripMarkdown(line.slice(summary[0].length)), 160);

    prose.push(stripMarkdown(line));
  }

  const first = prose.find((line) => line.length > 24);
  if (first) return truncate(first, 160);

  return locale === 'zh-CN'
    ? `${title}，${isoDate(date)} 发布。`
    : `${title}, published ${isoDate(date)}.`;
}
