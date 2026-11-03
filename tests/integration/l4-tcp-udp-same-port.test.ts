/** Regression for #376: TCP and UDP hosts on one port must get separate servers. */
import { describe, it, expect, vi } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});
vi.unmock('@/src/lib/caddy');

import { l4ProxyHosts } from '../../src/lib/db/schema';
import { buildL4Servers } from '../../src/lib/caddy';

const now = new Date().toISOString();
const host = (name: string, protocol: 'tcp' | 'udp', listenAddress: string) => ({
  name, protocol, listenAddress, upstreams: JSON.stringify(['10.0.0.1:21116']), matcherType: 'none' as const,
  matcherValue: null, tlsTermination: false, proxyProtocolVersion: null, proxyProtocolReceive: false,
  enabled: true, createdAt: now, updatedAt: now,
});

describe('buildL4Servers', () => {
  it('keeps TCP and UDP listeners on the same port', async () => {
    await ctx.db.insert(l4ProxyHosts).values([
      host('tcp', 'tcp', ':21116'), host('udp', 'udp', ':21116'), host('tcp2', 'tcp', ':21117'),
    ]);
    const servers = (await buildL4Servers()) as Record<string, any>;
    const listens = Object.values(servers).map((s) => s.listen[0]).sort();
    expect(listens).toEqual([':21116', ':21117', 'udp/:21116']);
    const udp = Object.values(servers).find((s) => s.listen[0] === 'udp/:21116');
    expect(udp.routes[0].handle[0].upstreams).toEqual([{ dial: ['udp/10.0.0.1:21116'] }]);
  });
});
