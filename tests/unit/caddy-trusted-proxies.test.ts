/**
 * Server-level trusted_proxies / client_ip_headers support (issue #222).
 *
 * Caddy resolves {http.vars.client_ip} in core, before any handler runs, so
 * the only place a global trusted-proxy list can correct client-IP attribution
 * (access logs, analytics, downstream handlers) is the HTTP server object
 * itself (servers.ingressi). These tests cover the pure builder plus the emission
 * into the generated Caddy document.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TestDb } from '../helpers/db';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

// Keep the real buildCaddyDocument but stub the network apply so createProxyHost
// doesn't try to reach a live Caddy admin API.
vi.mock('../../src/lib/caddy', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/caddy')>();
  return { ...actual, applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }) };
});

vi.mock('../../src/lib/audit', () => ({ logAuditEvent: vi.fn() }));

// Import order matters: the model/settings modules (which pull in the mocked
// caddy via a relative "../caddy" specifier) must load before we import from
// caddy directly, otherwise createProxyHost's applyCaddyConfig can resolve to
// the un-stubbed module and try to reach a live Caddy admin API.
import { createProxyHost } from '../../src/lib/models/proxy-hosts';
import { saveTrustedProxiesSettings, saveGeoBlockSettings, saveMetricsSettings, type GeoBlockSettings } from '../../src/lib/settings';
import { buildServerTrustedProxies, buildBlockerHandler, resolveEffectiveGeoBlock, buildCaddyDocument } from '../../src/lib/caddy';
import * as schema from '../../src/lib/db/schema';

const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', 'fd00::/8', '::1/128'];

function cpmServer(doc: unknown): Record<string, unknown> {
  return (doc as { apps?: { http?: { servers?: { ingressi?: Record<string, unknown> } } } })
    ?.apps?.http?.servers?.ingressi ?? {};
}

const baseGeoBlock: GeoBlockSettings = {
  enabled: true,
  block_countries: ['CN'],
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

describe('buildServerTrustedProxies', () => {
  it('returns an empty object when no settings are configured', () => {
    expect(buildServerTrustedProxies(null)).toEqual({});
    expect(buildServerTrustedProxies(undefined)).toEqual({});
  });

  it('returns an empty object when ranges is empty (feature disabled by default)', () => {
    expect(buildServerTrustedProxies({ ranges: [] })).toEqual({});
    expect(buildServerTrustedProxies({ ranges: ['  ', ''] })).toEqual({});
  });

  it('emits a static trusted_proxies source with the configured ranges', () => {
    expect(buildServerTrustedProxies({ ranges: ['172.21.0.1/32'] })).toEqual({
      trusted_proxies: { source: 'static', ranges: ['172.21.0.1/32'] },
    });
  });

  it('expands the private_ranges shorthand', () => {
    const result = buildServerTrustedProxies({ ranges: ['private_ranges'] });
    expect((result.trusted_proxies as { ranges: string[] }).ranges).toEqual(PRIVATE_RANGES);
  });

  it('trims and drops blank ranges', () => {
    const result = buildServerTrustedProxies({ ranges: ['  172.21.0.1/32 ', '', ' 10.1.2.3/32'] });
    expect((result.trusted_proxies as { ranges: string[] }).ranges).toEqual(['172.21.0.1/32', '10.1.2.3/32']);
  });

  it('emits client_ip_headers only when custom headers are set', () => {
    expect(buildServerTrustedProxies({ ranges: ['10.0.0.0/8'] }).client_ip_headers).toBeUndefined();
    expect(
      buildServerTrustedProxies({ ranges: ['10.0.0.0/8'], client_ip_headers: ['Cf-Connecting-Ip'] }).client_ip_headers
    ).toEqual(['Cf-Connecting-Ip']);
  });

  it('emits trusted_proxies_strict as 1 when strict is enabled', () => {
    expect(buildServerTrustedProxies({ ranges: ['10.0.0.0/8'] }).trusted_proxies_strict).toBeUndefined();
    expect(buildServerTrustedProxies({ ranges: ['10.0.0.0/8'], strict: true }).trusted_proxies_strict).toBe(1);
  });
});

describe('buildCaddyDocument server-level trusted proxies', () => {
  beforeEach(async () => {
    await ctx.db.delete(schema.proxyHosts);
    await ctx.db.delete(schema.settings);
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
    await createProxyHost(
      { name: 'plain', domains: ['app.example.com'], upstreams: ['10.0.0.5:8080'] },
      1
    );
  });

  it('does not emit trusted_proxies on servers.ingressi by default', async () => {
    const doc = await buildCaddyDocument();
    const server = cpmServer(doc);
    expect(server.trusted_proxies).toBeUndefined();
    expect(server.client_ip_headers).toBeUndefined();
    expect(server.trusted_proxies_strict).toBeUndefined();
  });

  it('emits trusted_proxies / client_ip_headers / strict on servers.ingressi when configured', async () => {
    await saveTrustedProxiesSettings({
      ranges: ['172.21.0.1/32'],
      client_ip_headers: ['Cf-Connecting-Ip'],
      strict: true,
    });

    const doc = await buildCaddyDocument();
    const server = cpmServer(doc);
    expect(server.trusted_proxies).toEqual({ source: 'static', ranges: ['172.21.0.1/32'] });
    expect(server.client_ip_headers).toEqual(['Cf-Connecting-Ip']);
    expect(server.trusted_proxies_strict).toBe(1);
  });

  it('leaves geoblock trusted_proxies untouched when default_geoblock is off', async () => {
    await saveTrustedProxiesSettings({ ranges: ['172.21.0.1/32'] });
    await saveGeoBlockSettings(baseGeoBlock);

    const doc = await buildCaddyDocument();
    const json = JSON.stringify(doc);
    // The blocker handler carries no trusted_proxies (geoblock list stayed empty).
    expect(json).toContain('"handler":"blocker"');
    const blocker = findBlocker(doc);
    expect(blocker?.trusted_proxies).toBeUndefined();
  });

  it('defaults the global geoblock trusted_proxies from the server list when default_geoblock is on', async () => {
    await saveTrustedProxiesSettings({ ranges: ['172.21.0.1/32'], default_geoblock: true });
    await saveGeoBlockSettings(baseGeoBlock);

    const doc = await buildCaddyDocument();
    const blocker = findBlocker(doc);
    expect(blocker?.trusted_proxies).toEqual(['172.21.0.1/32']);
  });

  it('does not emit listener_wrappers by default, or with only X-Forwarded-For ranges', async () => {
    expect(cpmServer(await buildCaddyDocument()).listener_wrappers).toBeUndefined();
    await saveTrustedProxiesSettings({ ranges: ['private_ranges'], strict: true });
    expect(cpmServer(await buildCaddyDocument()).listener_wrappers).toBeUndefined();
    await saveTrustedProxiesSettings({ ranges: [], proxy_protocol_ranges: [] });
    expect(cpmServer(await buildCaddyDocument()).listener_wrappers).toBeUndefined();
  });

  it('reads the PROXY header from the listed load balancers on servers.ingressi, before TLS', async () => {
    await saveTrustedProxiesSettings({ ranges: [], proxy_protocol_ranges: ['192.168.1.1', '10.0.10.0/24', '2001:db8::7'] });

    const server = cpmServer(await buildCaddyDocument());
    expect(server.listen).toEqual([':80', ':443']);
    expect(server.listener_wrappers).toEqual([
      { wrapper: 'proxy_protocol', allow: ['192.168.1.1/32', '10.0.10.0/24', '2001:db8::7/128'], fallback_policy: 'ignore' },
      { wrapper: 'tls' },
    ]);
    // X-Forwarded-For trust stays off: the two settings are independent.
    expect(server.trusted_proxies).toBeUndefined();
  });

  it('emits PROXY protocol alongside trusted proxies, strict mode and custom headers', async () => {
    await saveTrustedProxiesSettings({
      ranges: ['172.21.0.1/32'],
      client_ip_headers: ['Cf-Connecting-Ip'],
      strict: true,
      proxy_protocol_ranges: ['172.21.0.1'],
    });

    const server = cpmServer(await buildCaddyDocument());
    expect(server.trusted_proxies).toEqual({ source: 'static', ranges: ['172.21.0.1/32'] });
    expect(server.client_ip_headers).toEqual(['Cf-Connecting-Ip']);
    expect(server.trusted_proxies_strict).toBe(1);
    expect((server.listener_wrappers as Array<Record<string, unknown>>)[0].allow).toEqual(['172.21.0.1/32']);
  });

  it('drops stored entries that would widen the list (a replica receives what its master stored)', async () => {
    await saveTrustedProxiesSettings({ ranges: [], proxy_protocol_ranges: ['0.0.0.0/0', 'private_ranges', 'not-an-address', '198.51.100.4'] });
    const wrappers = cpmServer(await buildCaddyDocument()).listener_wrappers as Array<Record<string, unknown>>;
    expect(wrappers[0].allow).toEqual(['198.51.100.4/32']);

    await saveTrustedProxiesSettings({ ranges: [], proxy_protocol_ranges: ['::/0', 'nope'] });
    expect(cpmServer(await buildCaddyDocument()).listener_wrappers).toBeUndefined();
  });

  it('leaves the metrics server alone', async () => {
    await saveMetricsSettings({ enabled: true, port: 9090 });
    await saveTrustedProxiesSettings({ ranges: [], proxy_protocol_ranges: ['192.168.1.1'] });
    const doc = (await buildCaddyDocument()) as { apps: { http: { servers: Record<string, Record<string, unknown>> } } };
    expect(doc.apps.http.servers.metrics).toBeDefined();
    expect(doc.apps.http.servers.metrics.listener_wrappers).toBeUndefined();
    expect(doc.apps.http.servers.ingressi.listener_wrappers).toBeDefined();
  });

  it('does not override an explicitly-set geoblock trusted_proxies list', async () => {
    await saveTrustedProxiesSettings({ ranges: ['172.21.0.1/32'], default_geoblock: true });
    await saveGeoBlockSettings({ ...baseGeoBlock, trusted_proxies: ['10.9.9.9/32'] });

    const doc = await buildCaddyDocument();
    const blocker = findBlocker(doc);
    expect(blocker?.trusted_proxies).toEqual(['10.9.9.9/32']);
  });

  it('defaults the trusted_proxies of a host with its own geoblock rules and no global ones', async () => {
    await saveTrustedProxiesSettings({ ranges: ['172.21.0.1/32'], default_geoblock: true });
    await createProxyHost(
      { name: 'geo', domains: ['geo.example.com'], upstreams: ['10.0.0.6:8080'], geoblock: baseGeoBlock, geoblockMode: 'merge' },
      1
    );

    const blocker = findBlocker(await buildCaddyDocument());
    expect(blocker?.block_countries).toEqual(['CN']);
    expect(blocker?.trusted_proxies).toEqual(['172.21.0.1/32']);
  });

  it('defaults the trusted_proxies of a host whose geoblock rules override the global ones', async () => {
    await saveTrustedProxiesSettings({ ranges: ['172.21.0.1/32'], default_geoblock: true });
    await saveGeoBlockSettings({ ...baseGeoBlock, block_countries: ['RU'], trusted_proxies: ['10.9.9.9/32'] });
    await ctx.db.delete(schema.proxyHosts);
    await createProxyHost(
      { name: 'geo', domains: ['geo.example.com'], upstreams: ['10.0.0.6:8080'], geoblock: baseGeoBlock, geoblockMode: 'override' },
      1
    );

    const blocker = findBlocker(await buildCaddyDocument());
    expect(blocker?.block_countries).toEqual(['CN']);
    expect(blocker?.trusted_proxies).toEqual(['172.21.0.1/32']);
  });

  it('does not merge the rules of a disabled global geoblock into a host that merges with it', async () => {
    await saveGeoBlockSettings({ ...baseGeoBlock, enabled: false, block_countries: ['RU'], block_cidrs: ['0.0.0.0/0'] });
    await ctx.db.delete(schema.proxyHosts);
    await createProxyHost(
      { name: 'geo', domains: ['geo.example.com'], upstreams: ['10.0.0.6:8080'], geoblock: baseGeoBlock, geoblockMode: 'merge' },
      1
    );

    const blocker = findBlocker(await buildCaddyDocument());
    expect(blocker?.block_countries).toEqual(['CN']);
    expect(blocker?.block_cidrs).toBeUndefined();
  });
});

/** Find the first geoip blocker handler anywhere in the config document. */
function findBlocker(node: unknown): Record<string, unknown> | undefined {
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findBlocker(item);
      if (found) return found;
    }
  } else if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    if (obj.handler === 'blocker') return obj;
    for (const v of Object.values(obj)) {
      const found = findBlocker(v);
      if (found) return found;
    }
  }
  return undefined;
}

// Sanity: buildBlockerHandler / resolveEffectiveGeoBlock still imported & usable
describe('geoblock helpers remain reachable', () => {
  it('buildBlockerHandler emits trusted_proxies from a resolved config', () => {
    const resolved = resolveEffectiveGeoBlock({ ...baseGeoBlock, trusted_proxies: ['private_ranges'] }, {
      geoblock_mode: 'merge',
      geoblock: null,
    });
    const handler = buildBlockerHandler(resolved!);
    expect(handler.trusted_proxies).toEqual(PRIVATE_RANGES);
  });
});
