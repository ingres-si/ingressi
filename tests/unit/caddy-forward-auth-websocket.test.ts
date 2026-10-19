import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

// Keep the real buildCaddyDocument (pure config builder) but stub the network
// apply so createProxyHost doesn't try to reach a live Caddy admin API.
vi.mock('../../src/lib/caddy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/caddy')>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

import { createProxyHost } from '../../src/lib/models/proxy-hosts';
import { buildCaddyDocument, FORWARD_AUTH_SUBREQUEST_STRIP_HEADERS } from '../../src/lib/caddy';
import * as schema from '../../src/lib/db/schema';

/**
 * Regression: every forward-auth subrequest must drop the client's WebSocket
 * handshake headers. Otherwise Caddy turns the verify call into an upgrade,
 * the auth service drops it (Next.js closes upgrade requests it does not
 * serve), and every WebSocket on a protected host fails with 502 Bad Gateway
 * while plain requests keep working.
 */

const UPSTREAM = '10.0.0.5:8080';
const WS_HEADERS = ['Connection', 'Upgrade', 'Sec-WebSocket-Key', 'Sec-WebSocket-Version'];

type Handler = Record<string, unknown>;

function collectHandlers(node: unknown, out: Handler[] = []): Handler[] {
  if (Array.isArray(node)) {
    for (const item of node) collectHandlers(item, out);
  } else if (node && typeof node === 'object') {
    const obj = node as Handler;
    if (typeof obj.handler === 'string') out.push(obj);
    for (const v of Object.values(obj)) collectHandlers(v, out);
  }
  return out;
}

/** Forward-auth subrequests are reverse_proxy handlers that rewrite to a GET. */
function authSubrequests(doc: unknown): Handler[] {
  return collectHandlers(doc).filter(
    (h) => h.handler === 'reverse_proxy' && (h.rewrite as { method?: string } | undefined)?.method === 'GET'
  );
}

function deletes(h: Handler): string[] {
  return ((h.headers as { request?: { delete?: string[] } } | undefined)?.request?.delete) ?? [];
}

beforeEach(async () => {
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.users).catch(() => {});
  await ctx.db.insert(schema.users).values({
    id: 1,
    email: 'admin@example.com',
    name: 'Admin',
    role: 'admin',
    provider: 'credentials',
    subject: 'admin',
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
});

describe('forward-auth subrequests drop WebSocket handshake headers', () => {
  it('exports the full list', () => {
    for (const name of [...WS_HEADERS, 'Sec-WebSocket-Extensions', 'Sec-WebSocket-Protocol']) {
      expect(FORWARD_AUTH_SUBREQUEST_STRIP_HEADERS).toContain(name);
    }
  });

  const cases: Array<[string, Record<string, unknown>]> = [
    ['Ingressi forward auth', { ingressiForwardAuth: { enabled: true } }],
    ['Ingressi forward auth with excluded paths', { ingressiForwardAuth: { enabled: true, excluded_paths: ['/public/*'] } }],
    ['Authentik', { authentik: { enabled: true, outpostDomain: 'outpost.example.com', outpostUpstream: 'http://outpost:9000' } }],
    [
      'generic forward auth',
      { forwardAuth: { enabled: true, provider: 'authelia', authUpstream: 'http://authelia:9091', authEndpoint: '/api/authz/forward-auth' } },
    ],
  ];

  for (const [label, auth] of cases) {
    it(label, async () => {
      await createProxyHost(
        { name: `ws-${label}`, domains: ['ws.example.com'], upstreams: [UPSTREAM], allowWebsocket: true, ...auth },
        1
      );
      const doc = await buildCaddyDocument();
      const subs = authSubrequests(doc);
      expect(subs.length).toBeGreaterThan(0);
      for (const h of subs) {
        for (const name of WS_HEADERS) expect(deletes(h)).toContain(name);
      }
      // The request to the app itself keeps its upgrade headers.
      const appProxies = collectHandlers(doc).filter(
        (h) => h.handler === 'reverse_proxy' && JSON.stringify(h.upstreams ?? []).includes(UPSTREAM)
      );
      expect(appProxies.length).toBeGreaterThan(0);
      for (const h of appProxies) expect(deletes(h)).not.toContain('Upgrade');
    });
  }
});
