/**
 * Rate limiting in the generated Caddy configuration (src/lib/caddy-rate-limit.ts,
 * buildProxyRoutes in src/lib/caddy.ts):
 *  - inheritance of the global defaults (inherit, merge, override, opt-out);
 *  - the zones: client IP via {http.vars.client_ip} with IPv6 grouping,
 *    header and signed-in-user keys with a client-IP fallback, the allowlist
 *    on every zone, metrics off;
 *  - placement: the limiter is invoked first on every route of a host (main,
 *    location, excluded, protected, bypass, outpost and callback routes),
 *    before the WAF, the monetization gate, forward auth and the upstream; the
 *    signed-in-user limiter right before the upstream, after Ingressi forward auth;
 *  - the error route that names the limiting zone in the access log.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
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
import { createProxyHost, getProxyHost, updateProxyHost } from '../../src/lib/models/proxy-hosts';
import { getRateLimitSettings, saveErrorPagesSettings, saveLoggingSettings, saveRateLimitSettings, saveWafSettings } from '../../src/lib/settings';
import { buildCaddyDocument } from '../../src/lib/caddy';
import {
  buildHostRateLimit,
  buildRateLimitLogRoute,
  rateLimitContext,
  resolveEffectiveRateLimitRules,
} from '../../src/lib/caddy-rate-limit';
import type { RateLimitRule, RateLimitSettings } from '../../src/lib/rate-limit-rules';
import * as schema from '../../src/lib/db/schema';
import { insertMonetizedHost } from '../helpers/monetization';
import { resetMonetizationEngineForTests } from '../../ee/monetization/engine';

const UPSTREAM = '10.0.0.5:8080';
const LOCATION_UPSTREAM = '10.0.0.6:8080';

const ipRule: RateLimitRule = { path: '/login', methods: ['POST'], key: 'client_ip', events: 5, window: '1m' };
const headerRule: RateLimitRule = { path: '*', methods: [], key: 'header', header: 'X-Api-Key', events: 100, window: '1m' };
const userRule: RateLimitRule = { path: '/api/*', methods: [], key: 'forward_auth_user', events: 60, window: '1m' };

type Handler = Record<string, any>;
type Doc = Awaited<ReturnType<typeof buildCaddyDocument>>;

function server(doc: Doc): Record<string, any> {
  return (doc.apps as any).http.servers.ingressi;
}

function collectHandleArrays(node: unknown, out: Handler[][] = []): Handler[][] {
  if (Array.isArray(node)) {
    for (const item of node) collectHandleArrays(item, out);
  } else if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    if (Array.isArray(obj.handle)) out.push(obj.handle as Handler[]);
    for (const v of Object.values(obj)) collectHandleArrays(v, out);
  }
  return out;
}

/** Handle arrays of the server's routes (not the named routes themselves). */
function routeHandleArrays(doc: Doc): Handler[][] {
  return collectHandleArrays(server(doc).routes);
}

const dials = (h: Handler) => ((h?.upstreams as Array<{ dial?: string }>) ?? []).map((u) => u.dial);
const dialsTo = (h: Handler, dial: string) => dials(h).some((d) => d === dial);
const isUpstream = (h: Handler) => h?.handler === 'reverse_proxy' && !h.rewrite && (dials(h).includes(UPSTREAM) || dials(h).includes(LOCATION_UPSTREAM));
const isInvoke = (name: string) => (h: Handler) => h?.handler === 'invoke' && h.name === name;
const isVerify = (h: Handler) => h?.handler === 'reverse_proxy' && h.rewrite?.uri === '/api/forward-auth/verify';
const isCallback = (h: Handler) => h?.handler === 'reverse_proxy' && String(h.rewrite?.uri ?? '').startsWith('/api/forward-auth/callback');
const isGenericAuth = (h: Handler) => h?.handler === 'reverse_proxy' && h.rewrite?.uri === '/api/authz/forward-auth';
// The WAF sits in a subroute that lets WebSocket upgrades skip it.
const isWaf = (h: Handler) => h?.handler === 'waf' || (h?.handler === 'subroute' && JSON.stringify(h).includes('"handler":"waf"'));
const isGate = (h: Handler) => h?.handler === 'reverse_proxy' && h.rewrite?.uri === '/api/monetization/gate';

function zonesOf(doc: Doc, routeName: string): Record<string, Record<string, any>> {
  const route = server(doc).named_routes?.[routeName];
  expect(route, `named route ${routeName}`).toBeDefined();
  return Object.assign({}, ...route.handle.filter((h: Handler) => h.handler === 'rate_limit').map((h: Handler) => h.rate_limits));
}

async function host(name: string, extra: Record<string, unknown> = {}) {
  return createProxyHost({ name, domains: [`${name}.example.com`], upstreams: [UPSTREAM], ...extra }, 1);
}

beforeEach(async () => {
  resetMonetizationEngineForTests();
  await ctx.db.delete(schema.monetizationHosts);
  await ctx.db.delete(schema.proxyHosts);
  await ctx.db.delete(schema.settings);
  await ctx.db.delete(schema.users).catch(() => {});
  await ctx.db.insert(schema.users).values({
    id: 1, email: 'admin@example.com', name: 'Admin', role: 'admin', provider: 'credentials', subject: 'admin',
    status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  });
});

describe('resolveEffectiveRateLimitRules', () => {
  const global: RateLimitSettings = { enabled: true, rules: [ipRule], allowlist: [] };

  it('inherits the enabled defaults without host rules, or with host rules switched off', () => {
    expect(resolveEffectiveRateLimitRules(global, null)).toEqual([ipRule]);
    expect(resolveEffectiveRateLimitRules(global, { enabled: false, mode: 'override', rules: [headerRule] })).toEqual([ipRule]);
    expect(resolveEffectiveRateLimitRules({ ...global, enabled: false }, null)).toEqual([]);
  });

  it('merges, overrides, and opts out with override and no rules', () => {
    expect(resolveEffectiveRateLimitRules(global, { enabled: true, mode: 'merge', rules: [headerRule] })).toEqual([ipRule, headerRule]);
    expect(resolveEffectiveRateLimitRules(global, { enabled: true, mode: 'override', rules: [headerRule] })).toEqual([headerRule]);
    expect(resolveEffectiveRateLimitRules(global, { enabled: true, mode: 'override', rules: [] })).toEqual([]);
    // Disabled defaults are not merged in.
    expect(resolveEffectiveRateLimitRules({ ...global, enabled: false }, { enabled: true, mode: 'merge', rules: [headerRule] })).toEqual([headerRule]);
  });

  it('counts a rule repeated by the host and the defaults once', () => {
    expect(resolveEffectiveRateLimitRules(global, { enabled: true, mode: 'merge', rules: [{ ...ipRule }] })).toEqual([ipRule]);
  });
});

describe('buildHostRateLimit', () => {
  const context = rateLimitContext({ enabled: true, rules: [], allowlist: ['192.0.2.0/24', 'private_ranges'], ipv6Prefix: 56 });

  it('keys client-IP rules by {http.vars.client_ip}, grouped by the IPv6 prefix, with metrics off', () => {
    const result = buildHostRateLimit(7, [ipRule], context, false);
    expect(result.early).toEqual({ handler: 'invoke', name: 'ingressi_rl_h7' });
    expect(result.beforeUpstream).toBeNull();
    const [handler] = result.namedRoutes.ingressi_rl_h7.handle as Handler[];
    expect(handler.handler).toBe('rate_limit');
    expect(handler.disable_metrics).toBe(true);
    const [[name, zone]] = Object.entries(handler.rate_limits as Record<string, any>);
    expect(name).toMatch(/^ingressi_rl_h7_[0-9a-f]{12}_ip$/);
    expect(zone).toEqual({
      match: [{
        path: ['/login'],
        method: ['POST'],
        not: [{ client_ip: { ranges: ['192.0.2.0/24', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', 'fd00::/8', '::1/128'] } }],
      }],
      key: '{http.vars.client_ip}',
      window: '1m',
      max_events: 5,
      ipv6_prefix: 56,
    });
  });

  it('matches every path for "*", and leaves out the allowlist and the IPv6 prefix when unset', () => {
    const plain = rateLimitContext({ enabled: true, rules: [], allowlist: [], ipv6Prefix: 128 });
    const result = buildHostRateLimit(1, [{ ...ipRule, path: '*', methods: [] }], plain, false);
    const zone = Object.values((result.namedRoutes.ingressi_rl_h1.handle as Handler[])[0].rate_limits)[0] as Record<string, any>;
    expect(zone.match).toEqual([{}]);
    expect(zone).not.toHaveProperty('ipv6_prefix');
    expect(rateLimitContext(null)).toEqual({ allowlist: [], ipv6Prefix: 64 });
  });

  it('counts header rules by the header value, and requests without it by client IP, after the IP zones', () => {
    const result = buildHostRateLimit(3, [headerRule, ipRule], context, false);
    const [ipHandler, headerHandler] = result.namedRoutes.ingressi_rl_h3.handle as Handler[];
    expect(Object.keys(ipHandler.rate_limits).every((name) => name.endsWith('_ip'))).toBe(true);
    const zones = Object.entries(headerHandler.rate_limits as Record<string, any>);
    const present = zones.find(([name]) => name.endsWith('_hdr'))![1];
    const absent = zones.find(([name]) => name.endsWith('_hdr_ip'))![1];
    expect(present.key).toBe('{http.request.header.X-Api-Key}');
    expect(present.match[0].header).toEqual({ 'X-Api-Key': ['*'] });
    expect(present).not.toHaveProperty('ipv6_prefix');
    expect(absent.key).toBe('{http.vars.client_ip}');
    expect(absent.match[0].not).toContainEqual({ header: { 'X-Api-Key': ['*'] } });
    expect(absent.match[0].not[0].client_ip.ranges).toContain('192.0.2.0/24');
  });

  it('runs signed-in-user rules before the upstream with forward auth, matching the path early', () => {
    const result = buildHostRateLimit(4, [userRule], context, true);
    expect(result.beforeUpstream).toEqual({ handler: 'invoke', name: 'ingressi_rl_h4_user' });
    // The early route only remembers the path (rewrites may change it later).
    const [marks] = result.namedRoutes.ingressi_rl_h4.handle as Handler[];
    expect(marks.handler).toBe('subroute');
    const pathVar = Object.keys(marks.routes[0].handle[0]).find((key) => key !== 'handler')!;
    expect(marks.routes[0]).toEqual({ match: [{ path: ['/api/*'] }], handle: [{ handler: 'vars', [pathVar]: '1' }] });

    const zones = (result.namedRoutes.ingressi_rl_h4_user.handle as Handler[])[0].rate_limits as Record<string, any>;
    const user = Object.entries(zones).find(([name]) => name.endsWith('_user'))![1];
    const anonymous = Object.entries(zones).find(([name]) => name.endsWith('_user_ip'))![1];
    expect(user.key).toBe('{http.request.header.X-Ingressi-User-Id}');
    expect(user.match[0]).toMatchObject({ vars: { [pathVar]: ['1'] }, header: { 'X-Ingressi-User-Id': ['*'] } });
    expect(user.match[0]).not.toHaveProperty('path');
    expect(anonymous.key).toBe('{http.vars.client_ip}');
    expect(anonymous.match[0].not).toContainEqual({ header: { 'X-Ingressi-User-Id': ['*'] } });
  });

  it('counts signed-in-user rules by client IP on hosts without Ingressi forward auth', () => {
    const result = buildHostRateLimit(5, [userRule], context, false);
    expect(result.beforeUpstream).toBeNull();
    const zones = (result.namedRoutes.ingressi_rl_h5.handle as Handler[])[0].rate_limits as Record<string, any>;
    const [[name, zone]] = Object.entries(zones);
    expect(name).toMatch(/_user_ip$/);
    expect(zone).toMatchObject({ key: '{http.vars.client_ip}', match: [{ path: ['/api/*'] }] });
  });

  it('names zones per host and per rule, stably', () => {
    const a = Object.keys((buildHostRateLimit(1, [ipRule], context, false).namedRoutes.ingressi_rl_h1.handle as Handler[])[0].rate_limits);
    const again = Object.keys((buildHostRateLimit(1, [ipRule], context, false).namedRoutes.ingressi_rl_h1.handle as Handler[])[0].rate_limits);
    const other = Object.keys((buildHostRateLimit(2, [ipRule], context, false).namedRoutes.ingressi_rl_h2.handle as Handler[])[0].rate_limits);
    const burst = Object.keys((buildHostRateLimit(1, [ipRule, { ...ipRule, events: 2, window: '1s' }], context, false).namedRoutes.ingressi_rl_h1.handle as Handler[])[0].rate_limits);
    expect(again).toEqual(a);
    expect(other).not.toEqual(a);
    expect(burst).toHaveLength(2);
  });

  it('emits nothing without rules', () => {
    expect(buildHostRateLimit(1, [], context, true)).toEqual({ namedRoutes: {}, early: null, beforeUpstream: null });
  });
});

describe('generated configuration', () => {
  it('adds no limiter, named route or error route without rate limiting', async () => {
    await host('plain');
    const doc = await buildCaddyDocument();
    expect(server(doc)).not.toHaveProperty('named_routes');
    expect(JSON.stringify(doc)).not.toContain('rate_limit');
    expect(JSON.stringify(doc)).not.toContain('"invoke"');
  });

  it('invokes the limiter first on the main and location routes, before the WAF and the upstream', async () => {
    await saveWafSettings({ enabled: true, mode: 'On', load_owasp_crs: false, custom_directives: '' });
    const created = await host('app', {
      locationRules: [{ path: '/ws/*', upstreams: [LOCATION_UPSTREAM] }],
      pathBlocks: [{ path: '/blocked', status: 403 }],
      redirects: [{ from: '/old', to: '/new', status: 301 }],
      rateLimit: { rules: [ipRule] },
    });
    const doc = await buildCaddyDocument();
    const invoke = isInvoke(`ingressi_rl_h${created.id}`);
    const upstreamRoutes = routeHandleArrays(doc).filter((arr) => arr.some(isUpstream));
    expect(upstreamRoutes).toHaveLength(2);
    for (const arr of upstreamRoutes) {
      expect(arr.findIndex(invoke)).toBe(0);
      expect(arr.findIndex(isWaf)).toBeGreaterThan(0);
      // Path blocks and redirects (subroutes) come after the limiter too.
      const subroutes = arr.flatMap((h, index) => (h.handler === 'subroute' ? [index] : []));
      expect(subroutes.length).toBeGreaterThanOrEqual(3);
      expect(Math.min(...subroutes)).toBeGreaterThan(0);
    }
    expect(Object.keys(zonesOf(doc, `ingressi_rl_h${created.id}`))).toHaveLength(1);
  });

  it('covers excluded, location and protected routes, the callback and the user limiter with Ingressi forward auth', async () => {
    for (const [name, faMeta] of [
      ['full', { enabled: true }],
      ['excluded', { enabled: true, excluded_paths: ['/public/*'] }],
      ['protected', { enabled: true, protected_paths: ['/admin/*'] }],
    ] as const) {
      await ctx.db.delete(schema.proxyHosts);
      const created = await host(name, {
        ingressiForwardAuth: faMeta,
        locationRules: [{ path: '/ws/*', upstreams: [LOCATION_UPSTREAM] }],
        rateLimit: { rules: [ipRule, userRule] },
      });
      const doc = await buildCaddyDocument();
      const early = isInvoke(`ingressi_rl_h${created.id}`);
      const late = isInvoke(`ingressi_rl_h${created.id}_user`);
      const arrays = routeHandleArrays(doc);

      const callback = arrays.find((arr) => arr.some(isCallback))!;
      expect(callback.findIndex(early), `${name}: callback`).toBe(0);

      const upstreamRoutes = arrays.filter((arr) => arr.some(isUpstream));
      expect(upstreamRoutes.length, name).toBeGreaterThanOrEqual(2);
      for (const arr of upstreamRoutes) {
        const earlyAt = arr.findIndex(early);
        const lateAt = arr.findIndex(late);
        const upstreamAt = arr.findIndex(isUpstream);
        expect(earlyAt, `${name}: early limiter`).toBeGreaterThanOrEqual(0);
        expect(lateAt, `${name}: user limiter right before the upstream`).toBe(upstreamAt - 1);
        const verifyAt = arr.findIndex(isVerify);
        if (verifyAt >= 0) {
          expect(earlyAt).toBeLessThan(verifyAt);
          expect(lateAt).toBeGreaterThan(verifyAt);
        }
      }
      // Protected routes and unprotected ones both exist in every mode.
      expect(upstreamRoutes.some((arr) => arr.some(isVerify)), name).toBe(true);
    }
  });

  it('limits the generic forward-auth bypass and browser/API routes before the auth server', async () => {
    const created = await host('generic', {
      forwardAuth: { enabled: true, provider: 'authelia', authUpstream: 'http://authelia.example.com:9091', apiSplit: true, apiBypassHeaders: ['X-Api-Key'] },
      rateLimit: { rules: [ipRule, userRule] },
    });
    const doc = await buildCaddyDocument();
    const early = isInvoke(`ingressi_rl_h${created.id}`);
    const upstreamRoutes = routeHandleArrays(doc).filter((arr) => arr.some(isUpstream));
    expect(upstreamRoutes.length).toBeGreaterThanOrEqual(3); // bypass, browser, API
    for (const arr of upstreamRoutes) {
      const authAt = arr.findIndex(isGenericAuth);
      expect(arr.findIndex(early)).toBeGreaterThanOrEqual(0);
      if (authAt >= 0) expect(arr.findIndex(early)).toBeLessThan(authAt);
    }
    // No Ingressi forward auth: the user rule counts by client IP, early.
    expect(server(doc).named_routes).not.toHaveProperty(`ingressi_rl_h${created.id}_user`);
    expect(Object.keys(zonesOf(doc, `ingressi_rl_h${created.id}`)).some((name) => name.endsWith('_user_ip'))).toBe(true);
  });

  it('limits the Authentik outpost route too', async () => {
    const created = await host('ak', {
      authentik: { enabled: true, outpostDomain: 'outpost.goauthentik.io', outpostUpstream: 'http://authentik.example.com:9000' },
      rateLimit: { rules: [ipRule] },
    });
    const doc = await buildCaddyDocument();
    const outpost = routeHandleArrays(doc).find((arr) => arr.some((h) => h.handler === 'reverse_proxy' && dialsTo(h, 'authentik.example.com:9000') && !h.rewrite))!;
    expect(outpost.findIndex(isInvoke(`ingressi_rl_h${created.id}`))).toBe(0);
  });

  it('limits a monetized host before the gate, so floods never reach the per-consumer limit', async () => {
    const created = await host('api', { rateLimit: { rules: [ipRule] } });
    await insertMonetizedHost(ctx.db, created.id);
    const doc = await buildCaddyDocument();
    for (const arr of routeHandleArrays(doc).filter((a) => a.some(isUpstream))) {
      const limiter = arr.findIndex(isInvoke(`ingressi_rl_h${created.id}`));
      expect(limiter).toBeGreaterThanOrEqual(0);
      expect(limiter).toBeLessThan(arr.findIndex(isGate));
    }
  });

  it('applies the global defaults with the allowlist, and honours merge, override and opt-out', async () => {
    await saveRateLimitSettings({ enabled: true, rules: [ipRule], allowlist: ['198.51.100.7'], ipv6Prefix: 48 });
    const inherit = await host('inherit');
    const merge = await host('merge', { rateLimit: { mode: 'merge', rules: [headerRule] } });
    const override = await host('override', { rateLimit: { mode: 'override', rules: [{ ...ipRule, events: 50 }] } });
    const optOut = await host('optout', { rateLimit: { mode: 'override', rules: [] } });
    const doc = await buildCaddyDocument();

    const inheritZones = Object.values(zonesOf(doc, `ingressi_rl_h${inherit.id}`));
    expect(inheritZones).toHaveLength(1);
    expect(inheritZones[0]).toMatchObject({ max_events: 5, ipv6_prefix: 48, match: [{ not: [{ client_ip: { ranges: ['198.51.100.7'] } }] }] });

    const mergeZones = zonesOf(doc, `ingressi_rl_h${merge.id}`);
    expect(Object.keys(mergeZones).map((name) => name.replace(/^.*_[0-9a-f]{12}_/, '')).sort()).toEqual(['hdr', 'hdr_ip', 'ip']);
    for (const zone of Object.values(mergeZones)) {
      expect(zone.match[0].not[0]).toEqual({ client_ip: { ranges: ['198.51.100.7'] } });
    }

    expect(Object.values(zonesOf(doc, `ingressi_rl_h${override.id}`)).map((zone) => zone.max_events)).toEqual([50]);
    expect(server(doc).named_routes).not.toHaveProperty(`ingressi_rl_h${optOut.id}`);
    const optOutRoutes = routeHandleArrays(doc).filter((arr) => arr.some(isUpstream) && JSON.stringify(arr).includes('invoke'));
    expect(optOutRoutes.every((arr) => !arr.some(isInvoke(`ingressi_rl_h${optOut.id}`)))).toBe(true);
  });

  it('turns every host off with the defaults off, while host rules still apply', async () => {
    await saveRateLimitSettings({ enabled: false, rules: [ipRule], allowlist: [] });
    const inherit = await host('inherit');
    const own = await host('own', { rateLimit: { rules: [headerRule] } });
    const doc = await buildCaddyDocument();
    expect(server(doc).named_routes).not.toHaveProperty(`ingressi_rl_h${inherit.id}`);
    expect(server(doc).named_routes).toHaveProperty(`ingressi_rl_h${own.id}`);
  });

  it('names the limiting zone in the access log before the custom error pages', async () => {
    await saveLoggingSettings({ enabled: true, format: 'json' });
    await saveErrorPagesSettings({ rules: [{ statuses: [429], body: 'Slow down' }] });
    await host('app', { rateLimit: { rules: [ipRule] } });
    const doc = await buildCaddyDocument();
    const errors = server(doc).errors.routes as Handler[];
    expect(errors[0]).toEqual(buildRateLimitLogRoute());
    expect(errors[0]).toEqual({
      match: [{ not: [{ vars: { '{http.rate_limit.exceeded.name}': [''] } }] }],
      handle: [{ handler: 'log_append', key: 'rate_limit_zone', value: '{http.rate_limit.exceeded.name}' }],
    });
    expect(errors[0]).not.toHaveProperty('terminal');
    expect(errors[1].handle[0].body).toBe('Slow down');
  });

  it('adds no error route without access logging, where nothing would read the field', async () => {
    await host('app', { rateLimit: { rules: [ipRule] } });
    const doc = await buildCaddyDocument();
    expect(server(doc)).not.toHaveProperty('errors');
    expect(server(doc)).toHaveProperty('named_routes');
  });
});

describe('the proxy host model', () => {
  it('stores, keeps on unrelated updates, and removes per-host rate limiting', async () => {
    const created = await host('app', { rateLimit: { mode: 'override', rules: [{ path: '/login', methods: ['post'], events: 3, window: '30s' }] } });
    expect(created.rateLimit).toEqual({
      enabled: true,
      mode: 'override',
      rules: [{ path: '/login', methods: ['POST'], key: 'client_ip', events: 3, window: '30s' }],
    });

    await updateProxyHost(created.id, { name: 'renamed' }, 1);
    expect((await getProxyHost(created.id))!.rateLimit).toEqual(created.rateLimit);

    await updateProxyHost(created.id, { rateLimit: { enabled: false, rules: [] } }, 1);
    expect((await getProxyHost(created.id))!.rateLimit).toBeNull();

    await updateProxyHost(created.id, { rateLimit: { rules: [ipRule] } }, 1);
    await updateProxyHost(created.id, { rateLimit: null }, 1);
    expect((await getProxyHost(created.id))!.rateLimit).toBeNull();
  });

  it('refuses an invalid rule without saving anything', async () => {
    const created = await host('app');
    await expect(
      updateProxyHost(created.id, { rateLimit: { rules: [{ path: '/{http.request.host}', events: 5, window: '1m' }] } } as never, 1)
    ).rejects.toThrow(/rateLimit\.rules\[0\]\.path/);
    await expect(host('bad', { rateLimit: { rules: [{ events: 5000, window: '1m' }] } })).rejects.toThrow(/events/);
    expect((await getProxyHost(created.id))!.rateLimit).toBeNull();
  });

  it('reads the global defaults back normalized', async () => {
    await saveRateLimitSettings({ enabled: true, rules: [{ ...ipRule, methods: ['post'] }], allowlist: [' 192.0.2.1 '] } as never);
    expect(await getRateLimitSettings()).toEqual({ enabled: true, rules: [ipRule], allowlist: ['192.0.2.1'] });
  });
});
