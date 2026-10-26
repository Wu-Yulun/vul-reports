import { defineCollection } from 'astro:content';
import { z } from 'astro/zod';
import fs from 'node:fs/promises';
import path from 'node:path';

/**
 * Reports live at the repository root as `<date>/<software>/readme.md` and
 * `readme.<locale>.md`, next to their `img/` folder. They are read in place:
 * nothing is copied, renamed or rewritten, and adding a report means dropping
 * a folder in — the site picks it up on the next build.
 *
 * The built-in glob loader cannot do this: it resolves its `base` against the
 * Astro project root, and refuses to leave `src/content`.
 */

const repoRoot = process.cwd();
const reportName = /^readme(?:\.([A-Za-z-]+))?\.md$/;
const dateName = /^\d{8}$/;

/** Locale directory prefix used in URLs, e.g. `zh-CN`. */
const DEFAULT_LOCALE = 'en';

export interface ReportSource {
  /** Starlight-free slug: `20261024/free-fs` or `zh-CN/20261024/free-fs`. */
  id: string;
  /** Path relative to the repository root. */
  filePath: string;
  absolutePath: string;
  /** Directory name of the report, e.g. `free-fs`. */
  software: string;
  /** Directory name of the date, e.g. `20261024`. */
  date: string;
  locale: string;
}

/** Reads `# Title` from the first heading of the report. */
function extractTitle(body: string): string {
  const match = body.match(/^#[ \t]+(.+)$/m);
  return match ? match[1].trim() : 'Untitled report';
}

async function collectReports(): Promise<ReportSource[]> {
  const reports: ReportSource[] = [];

  const dates = (await fs.readdir(repoRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && dateName.test(entry.name))
    .map((entry) => entry.name)
    .sort();

  for (const date of dates) {
    const softwares = (await fs.readdir(path.join(repoRoot, date), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory() && !entry.name.startsWith('.'))
      .map((entry) => entry.name)
      .sort();

    for (const software of softwares) {
      const dir = `${date}/${software}`;
      const files = await fs.readdir(path.join(repoRoot, dir), { withFileTypes: true });

      for (const file of files) {
        const match = file.name.match(reportName);
        if (!file.isFile() || !match) continue;

        const locale = match[1] ?? DEFAULT_LOCALE;
        reports.push({
          id: locale === DEFAULT_LOCALE ? dir : `${locale}/${dir}`,
          filePath: `${dir}/${file.name}`,
          absolutePath: path.join(repoRoot, dir, file.name),
          software,
          date,
          locale,
        });
      }
    }
  }

  return reports;
}

const docs = defineCollection({
  schema: z.object({
    title: z.string(),
    locale: z.string(),
    software: z.string(),
    date: z.string(),
    /** Path of the source file relative to the repository root. */
    sourcePath: z.string(),
    body: z.string(),
  }),
  loader: {
    name: 'vul-reports-loader',
    load: async ({ store, logger, parseData, watcher, generateDigest }) => {
      const reports = await collectReports();
      const seen = new Set<string>();

      for (const report of reports) {
        const body = await fs.readFile(report.absolutePath, 'utf8');
        seen.add(report.id);

        const existing = store.get(report.id);
        const digest = generateDigest(body);
        if (existing && existing.digest === digest && existing.filePath === report.filePath) {
          if (existing.deferredRender) store.addModuleImport(existing.filePath);
          if (existing.assetImports?.length) store.addAssetImports(existing.assetImports, existing.filePath);
          continue;
        }

        try {
          const data = await parseData({
            id: report.id,
            filePath: report.filePath,
            data: {
              title: extractTitle(body),
              locale: report.locale,
              software: report.software,
              date: report.date,
              sourcePath: report.filePath,
              body,
            },
          });
          store.set({
            id: report.id,
            data,
            body,
            filePath: report.filePath,
            digest,
            deferredRender: true,
          });
        } catch (error) {
          logger.error(`Error loading ${report.filePath}: ${error.message}`);
          throw error;
        }
      }

      for (const id of store.keys()) {
        if (!seen.has(id)) store.delete(id);
      }

      watcher?.add(repoRoot);
    },
  },
});

export const collections = { docs };
