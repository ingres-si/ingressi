import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));
vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});
vi.mock('../../src/lib/caddy', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/caddy')>()),
  applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }),
}));
vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

import { buildCaddyDocument } from '../../src/lib/caddy';
import { saveWafSettings } from '../../src/lib/settings';
import * as schema from '../../src/lib/db/schema';

function handlers(value: unknown): Record<string, unknown>[] {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap(handlers);
  const obj = value as Record<string, unknown>;
  return [...(typeof obj.handler === 'string' ? [obj] : []), ...Object.values(obj).flatMap(handlers)];
}

beforeEach(async () => {
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.settings);
  await ctx.db.delete(schema.users);
  const now = new Date().toISOString();
  await ctx.db.insert(schema.users).values({ id: 1, email: 'admin@example.test', name: 'Admin', role: 'admin', provider: 'credentials', subject: 'admin', status: 'active', createdAt: now, updatedAt: now });
});

describe('server-generated WAF transaction ID in access logs', () => {
  it.each([
    ['On', false], ['On', true], ['DetectionOnly', false], ['DetectionOnly', true],
  ] as const)('wraps %s WAF before execution, evaluating its ID on return (WebSockets=%s)', async (mode, allowWebsocket) => {
    await saveWafSettings({ enabled: true, mode, load_owasp_crs: false, custom_directives: '' });
    await ctx.db.insert(schema.proxyHosts).values({ name: 'test', domains: '["example.test"]', upstreams: '["http://127.0.0.1:8080"]', allowWebsocket, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
    const all = handlers(await buildCaddyDocument());
    const log = all.findIndex(h => h.handler === 'log_append' && h.key === 'waf_transaction_id');
    const waf = all.findIndex(h => h.handler === 'waf');
    expect(log).toBeGreaterThanOrEqual(0);
    expect(waf).toBeGreaterThan(log);
    expect(all[log]).toEqual({ handler: 'log_append', key: 'waf_transaction_id', value: '{http.transaction_id}' });
    expect(all[log].early).not.toBe(true);
  });

  it('does not add a transaction logger when WAF is off', async () => {
    await saveWafSettings({ enabled: true, mode: 'Off', load_owasp_crs: false, custom_directives: '' });
    await ctx.db.insert(schema.proxyHosts).values({ name: 'test', domains: '["example.test"]', upstreams: '["http://127.0.0.1:8080"]', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
    expect(handlers(await buildCaddyDocument()).some(h => h.key === 'waf_transaction_id' || h.handler === 'waf')).toBe(false);
  });
});
