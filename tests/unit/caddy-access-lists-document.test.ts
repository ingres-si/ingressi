/**
 * Access list rules in the generated Caddy document (buildCaddyDocument):
 *  - a list with rules is a named route the hosts using it invoke, after geo
 *    blocking and before the list's basic auth;
 *  - a basic-auth-only list compiles exactly as before (no named route, no
 *    invoke, the same authentication handler);
 *  - the global Blocked sources list is the first server route, for every
 *    request, and only denies;
 *  - expired rules, invalid stored values and system lists attached to a
 *    host are left out; trusted proxies switch remote_ip to client_ip.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
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

// Models and settings before src/lib/caddy (see the caddy test mock import order note).
import { createProxyHost } from '../../src/lib/models/proxy-hosts';
import { addBlockedSource, createAccessList } from '../../src/lib/models/access-lists';
import { saveGeoBlockSettings, saveTrustedProxiesSettings, type GeoBlockSettings } from '../../src/lib/settings';
import { buildAccessListCaddyConfig, buildCaddyDocument } from '../../src/lib/caddy';
import * as schema from '../../src/lib/db/schema';

type Handler = Record<string, any>;
type Doc = Awaited<ReturnType<typeof buildCaddyDocument>>;

function server(doc: Doc): Record<string, any> {
  return (doc.apps as any).http.servers.ingressi;
}

/** The handle array of the host's main route (the catch-all for its domains). */
function hostHandle(doc: Doc, domain: string): Handler[] {
  const routes = server(doc).routes as Array<Record<string, any>>;
  const route = routes.find(
    (item) => item.match?.[0]?.host?.includes(domain) && !item.match[0].expression && !item.match[0].path
  );
  expect(route, `route of ${domain}`).toBeDefined();
  return route!.handle;
}

const geoblock: GeoBlockSettings = {
  enabled: true,
  block_countries: ['KP'],
  block_continents: [],
  block_asns: [],
  block_cidrs: [],
  block_ips: [],
  allow_countries: [],
  allow_continents: [],
  allow_asns: [],
  allow_cidrs: [],
  allow_ips: [],
  trusted_proxies: [],
  fail_closed: false,
  response_status: 403,
  response_body: 'Forbidden',
  response_headers: {},
  redirect_url: '',
};

async function host(name: string, accessListId: number | null) {
  return createProxyHost({ name, domains: [`${name}.example.com`], upstreams: ['10.0.0.5:8080'], accessListId }, 1);
}

beforeEach(async () => {
  for (const table of [schema.proxyHosts, schema.accessListRules, schema.accessListEntries, schema.accessLists, schema.settings]) {
    await ctx.db.delete(table);
  }
  await ctx.db.delete(schema.users).catch(() => {});
  await ctx.db.insert(schema.users).values({
    id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials', subject: 'admin',
    status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  });
});

describe('access lists in buildCaddyDocument', () => {
  it('invokes a list with rules from every host using it, after geo blocking and before basic auth', async () => {
    await saveGeoBlockSettings(geoblock);
    const list = await createAccessList(
      {
        name: 'Office and VPN',
        defaultAction: 'deny',
        rules: [{ action: 'allow', kind: 'ip', values: ['203.0.113.0/26'] }],
        users: [{ username: 'alice', password: 'Alice-Passw0rd!' }],
      },
      1
    );
    await host('office', list.id);
    await host('vpn', list.id);
    await host('open', null);

    const doc = await buildCaddyDocument();
    const name = `ingressi_acl_${list.id}`;
    expect(server(doc).named_routes[name]).toEqual({
      handle: [
        {
          handler: 'subroute',
          routes: [
            {
              match: [{ not: [{ remote_ip: { ranges: ['203.0.113.0/26'] } }] }],
              handle: [
                { handler: 'log_append', key: 'access_list', value: String(list.id) },
                { handler: 'static_response', status_code: 403, body: 'Forbidden' },
              ],
            },
          ],
        },
      ],
    });

    for (const domain of ['office.example.com', 'vpn.example.com']) {
      const handle = hostHandle(doc, domain);
      const geo = handle.findIndex((h) => h.handler === 'blocker');
      const invoke = handle.findIndex((h) => h.handler === 'invoke' && h.name === name);
      const auth = handle.findIndex((h) => h.handler === 'authentication');
      const upstream = handle.findIndex((h) => h.handler === 'reverse_proxy');
      expect(geo).toBeGreaterThanOrEqual(0);
      expect(invoke).toBe(geo + 1);
      expect(auth).toBeGreaterThan(invoke);
      expect(upstream).toBeGreaterThan(auth);
    }
    expect(hostHandle(doc, 'open.example.com').some((h) => h.handler === 'invoke')).toBe(false);
  });

  it('compiles a basic-auth-only list as before: no named route and the same authentication handler', async () => {
    const list = await createAccessList({ name: 'Staff', users: [{ username: 'bob', password: 'Bob-Passw0rd!' }] }, 1);
    await host('staff', list.id);

    const doc = await buildCaddyDocument();
    expect(server(doc).named_routes).toBeUndefined();
    const handle = hostHandle(doc, 'staff.example.com');
    expect(handle.some((h) => h.handler === 'invoke')).toBe(false);
    const auth = handle.find((h) => h.handler === 'authentication')!;
    expect(Object.keys(auth.providers.http_basic.accounts[0])).toEqual(['username', 'password']);
    expect(auth.providers.http_basic.accounts[0].username).toBe('bob');
    expect(auth.providers.http_basic.accounts[0].password).toMatch(/^\$2[aby]\$/);
  });

  it('uses client_ip when trusted proxies are configured', async () => {
    await saveTrustedProxiesSettings({ ranges: ['private_ranges'] });
    const list = await createAccessList({ name: 'Blocklist', rules: [{ action: 'deny', kind: 'ip', values: ['198.51.100.0/24'] }] }, 1);
    await host('app', list.id);

    const doc = await buildCaddyDocument();
    const routes = server(doc).named_routes[`ingressi_acl_${list.id}`].handle[0].routes;
    expect(routes[0].match).toEqual([{ client_ip: { ranges: ['198.51.100.0/24'] } }]);
  });

  it('puts Blocked sources first on the server, for every request, without a host matcher', async () => {
    await host('app', null);
    await addBlockedSource({ address: '198.51.100.19', reason: 'Scanner' }, 1);
    await addBlockedSource({ kind: 'asn', value: 'AS64500' }, 1);

    const doc = await buildCaddyDocument();
    const [first, ...rest] = server(doc).routes as Array<Record<string, any>>;
    expect(first).toEqual({
      handle: [
        {
          handler: 'subroute',
          routes: [
            {
              match: [{ remote_ip: { ranges: ['198.51.100.19'] } }],
              handle: [
                { handler: 'log_append', key: 'access_list', value: 'blocked_sources' },
                { handler: 'static_response', status_code: 403, body: 'Forbidden' },
              ],
            },
            {
              handle: [
                expect.objectContaining({ handler: 'blocker', block_asns: [64500], response_status: 403 }),
              ],
            },
          ],
        },
      ],
    });
    expect(first).not.toHaveProperty('terminal');
    expect(rest.length).toBeGreaterThan(0);
    // The list never becomes a host's named route.
    expect(server(doc).named_routes).toBeUndefined();
  });

  it('leaves out expired rules, and stays out of the way when nothing is blocked', async () => {
    await host('app', null);
    const { entry } = await addBlockedSource({ address: '198.51.100.19', expiresInSeconds: 3600 }, 1);
    await ctx.db.update(schema.accessListRules).set({ expiresAt: new Date(Date.now() - 1000).toISOString() });
    expect(entry.expiresAt).not.toBeNull();

    const doc = await buildCaddyDocument();
    const routes = server(doc).routes as Array<Record<string, any>>;
    expect(routes[0].match).toBeDefined();
    expect(JSON.stringify(routes)).not.toContain('198.51.100.19');
  });
});

describe('buildAccessListCaddyConfig', () => {
  const now = new Date().toISOString();
  const row = (overrides: Partial<typeof schema.accessLists.$inferSelect>) => ({
    id: 1, name: 'List', description: null, createdBy: null, createdAt: now, updatedAt: now,
    defaultAction: 'allow', denyStatus: 403, denyBody: null, denyRedirectUrl: null, failClosed: false, skipAuthForAllowed: false, systemKey: null,
    ...overrides,
  });
  const rule = (overrides: Partial<typeof schema.accessListRules.$inferSelect>) => ({
    id: 1, accessListId: 1, position: 0, action: 'deny', kind: 'ip', matchValues: '["198.51.100.19"]', note: null,
    expiresAt: null, createdBy: null, createdAt: now, updatedAt: now,
    ...overrides,
  });

  it('drops stored values that do not parse, and rules of unknown actions or kinds', () => {
    const config = buildAccessListCaddyConfig(
      [row({})],
      [
        rule({ id: 1, matchValues: '["198.51.100.19", "not-an-ip", "010.0.0.1"]' }),
        rule({ id: 2, position: 1, kind: 'city', matchValues: '["Rome"]' }),
        rule({ id: 3, position: 2, action: 'maybe' }),
        rule({ id: 4, position: 3, matchValues: '{"oops": true}' }),
      ],
      null
    );
    expect((config.namedRoutes.ingressi_acl_1 as any).handle[0].routes).toEqual([
      { match: [{ remote_ip: { ranges: ['198.51.100.19'] } }], handle: expect.any(Array) },
    ]);
  });

  it('exposes the allowed addresses as the Basic Auth bypass only when skipAuthForAllowed is on (#374)', () => {
    const rules = [
      rule({ id: 1, action: 'allow', matchValues: '["10.1.0.0/16"]' }),
      rule({ id: 2, position: 1, action: 'allow', kind: 'country', matchValues: '["IT"]' }),
    ];
    expect(buildAccessListCaddyConfig([row({})], rules, null).authBypassMatchers.size).toBe(0);
    const on = buildAccessListCaddyConfig([row({ skipAuthForAllowed: true })], rules, null);
    expect(on.authBypassMatchers.get(1)).toEqual({ remote_ip: { ranges: ['10.1.0.0/16'] } });
    expect(buildAccessListCaddyConfig([row({ skipAuthForAllowed: true })], [], null).authBypassMatchers.size).toBe(0);
  });

  it('orders rules by position, then id', () => {
    const config = buildAccessListCaddyConfig(
      [row({})],
      [
        rule({ id: 9, position: 1, action: 'deny', matchValues: '["10.0.0.0/8"]' }),
        rule({ id: 3, position: 0, action: 'allow', matchValues: '["10.1.0.0/16"]' }),
      ],
      null
    );
    expect((config.namedRoutes.ingressi_acl_1 as any).handle[0].routes[0].match).toEqual([
      { remote_ip: { ranges: ['10.0.0.0/8'] }, not: [{ remote_ip: { ranges: ['10.1.0.0/16'] } }] },
    ]);
  });

  it('serves the default response for a deny response that is not valid', () => {
    const config = buildAccessListCaddyConfig([row({ denyStatus: 200, denyRedirectUrl: 'javascript:alert(1)' })], [rule({})], null);
    expect((config.namedRoutes.ingressi_acl_1 as any).handle[0].routes[0].handle[1]).toEqual({
      handler: 'static_response', status_code: 403, body: 'Forbidden',
    });
  });

  it('keeps Blocked sources to deny rules and its default to allow, and never invokes it per host', () => {
    const config = buildAccessListCaddyConfig(
      [row({ id: 5, systemKey: 'blocked_sources', defaultAction: 'deny' })],
      [rule({ accessListId: 5, action: 'allow', matchValues: '["10.0.0.0/8"]' })],
      null
    );
    expect(config.blockedSourcesRoute).toBeNull();
    expect(config.invokes.size).toBe(0);
    // Unknown system lists are ignored.
    expect(buildAccessListCaddyConfig([row({ systemKey: 'something_else' })], [rule({})], null).invokes.size).toBe(0);
  });
});
