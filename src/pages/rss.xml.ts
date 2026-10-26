import type { APIRoute } from 'astro';
import { buildFeed } from '../lib/feed';

export const prerender = true;

export const GET: APIRoute = async () => {
  const xml = await buildFeed('en');

  return new Response(xml, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' },
  });
};
