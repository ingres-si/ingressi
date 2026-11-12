/**
 * Admin API over a unix socket (CADDY_ADMIN_SOCKET). When set, the generated
 * Caddy document must put the admin endpoint on the socket (no TCP :2019 that
 * proxied traffic in the Caddy container could dial) and dial the metrics
 * reverse-proxy over the same socket. When unset, the TCP admin block stays.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});
vi.mock('../../src/lib/caddy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/caddy')>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});
vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

import { saveMetricsSettings } from '../../src/lib/settings';
import { buildCaddyDocument } from '../../src/lib/caddy';
import { config } from '../../src/lib/config';

const SOCKET = '/run/caddy-admin/admin.sock';

function metricsDial(doc: Awaited<ReturnType<typeof buildCaddyDocument>>): string {
  const servers = (doc as any).apps.http.servers;
  return servers.metrics.routes[0].handle[0].upstreams[0].dial;
}

afterEach(() => {
  (config as { caddyAdminSocket: string | null }).caddyAdminSocket = null;
});

describe('Caddy admin API over a unix socket', () => {
  it('puts the admin endpoint on the socket and drops the TCP origins', async () => {
    (config as { caddyAdminSocket: string | null }).caddyAdminSocket = SOCKET;
    const doc = await buildCaddyDocument();
    expect((doc as any).admin).toEqual({ listen: `unix/${SOCKET}|0660` });
    // No TCP admin port anywhere in the document.
    expect(JSON.stringify(doc)).not.toContain('0.0.0.0:2019');
  });

  it('dials the metrics reverse-proxy over the socket, not localhost:2019', async () => {
    (config as { caddyAdminSocket: string | null }).caddyAdminSocket = SOCKET;
    await saveMetricsSettings({ enabled: true, port: 9090 });
    const doc = await buildCaddyDocument();
    expect(metricsDial(doc)).toBe(`unix/${SOCKET}`);
  });

  it('keeps the TCP admin block when no socket is configured', async () => {
    (config as { caddyAdminSocket: string | null }).caddyAdminSocket = null;
    const doc = await buildCaddyDocument();
    expect((doc as any).admin).toEqual({
      listen: '0.0.0.0:2019',
      origins: ['caddy:2019', 'localhost:2019', 'localhost'],
    });
  });
});
