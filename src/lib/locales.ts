export const LOCALES = {
  en: { label: 'English', home: '/', dateFormat: (date: string) => formatDate(date) },
  'zh-CN': { label: '中文', home: '/zh-CN/', dateFormat: (date: string) => formatDate(date) },
} as const;

export type Locale = keyof typeof LOCALES;

/** `20261024` -> `2026-10-24`. */
export function formatDate(date: string): string {
  const match = date.match(/^(\d{4})(\d{2})(\d{2})$/);
  if (!match) return date;
  const [, year, month, day] = match;
  return `${year}-${month}-${day}`;
}
