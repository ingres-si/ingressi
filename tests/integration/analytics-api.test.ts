/**
 * /api/v1/analytics over a real database with a mocked ClickHouse client:
 * the permission every route names, input validation (400 before any query
 * runs), bound parameters, the tag scope, the "disabled" /
 * "unavailable" fallbacks, saved views with their sharing rules and audit
 * events, and the OpenAPI entries.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import type { TestDb } from '../helpers/db';
import type { Access } from '../../src/lib/permissions';

const ctx = vi.hoisted(() => ({
  db: null as unknown as TestDb,
  access: null as unknown as Access,
  enabled: true,
  fail: false,
  seen: [] as string[],
  calls: [] as { query: string; query_params: Record<string, unknown> }[],
  rows: (() => []) as (query: string) => unknown[],
}));

vi.mock('../../src/lib/db', async () => {
  const { createTestDb } = await import('../helpers/db');
  ctx.db = createTestDb();
  return (await import('../helpers/db-module')).mockDbModule(() => ctx.db);
});

vi.mock('../../src/lib/clickhouse/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/clickhouse/client')>();
  return {
    ...actual,
    isAnalyticsEnabled: () => ctx.enabled,
    getRetentionDays: () => 30,
    queryDistinctHostsAll: async () => ctx.seen,
    getClient: () => ({
      query: async (args: { query: string; query_params: Record<string, unknown> }) => {
        ctx.calls.push(args);
        if (ctx.fail) throw Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8123'), { code: 'ECONNREFUSED' });
        return { json: async () => ctx.rows(args.query) };
      },
    }),
  };
});

vi.mock('../../src/lib/api-auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/lib/api-auth')>();
  const { can } = await import('../../src/lib/permissions');
  return {
    ...actual,
    requireApiPermission: vi.fn(async (_request: unknown, permission: string) => {
      if (!can(ctx.access, permission as never)) throw new actual.ApiAuthError(`Permission required: ${permission}`, 403);
      return { userId: ctx.access.userId, role: ctx.access.role, authMethod: 'bearer', access: ctx.access };
    }),
  };
});

import { GET as getQuery } from '../../app/api/v1/analytics/query/route';
import { GET as getTop } from '../../app/api/v1/analytics/top/route';
import { GET as getRequests } from '../../app/api/v1/analytics/requests/route';
import { GET as getHosts } from '../../app/api/v1/analytics/hosts/route';
import { GET as getHost } from '../../app/api/v1/analytics/hosts/[id]/route';
import { GET as getSeries } from '../../app/api/v1/analytics/security/series/route';
import { GET as getRules } from '../../app/api/v1/analytics/security/rules/route';
import { GET as getSources } from '../../app/api/v1/analytics/security/sources/route';
import { GET as getEvents } from '../../app/api/v1/analytics/security/events/route';
import { GET as getSecurityHosts } from '../../app/api/v1/analytics/security/hosts/route';
import { GET as getSignals } from '../../app/api/v1/analytics/signals/route';
import { GET as listViews, POST as createView } from '../../app/api/v1/analytics/views/route';
import { DELETE as deleteView, GET as getView, PATCH as patchView } from '../../app/api/v1/analytics/views/[id]/route';
import { GET as getOpenApi } from '../../app/api/v1/openapi.json/route';
import * as schema from '../../src/lib/db/schema';
import { adminAccess, type Permission } from '../../src/lib/permissions';
import { logAuditEvent } from '../../src/lib/audit';
import { deleteUser } from '../../src/lib/models/user';


function req(path: string, init?: { method?: string; body?: unknown }): NextRequest {
  return new NextRequest(`http://localhost${path}`, {
    method: init?.method ?? 'GET',
    ...(init?.body !== undefined ? { body: JSON.stringify(init.body), headers: { 'content-type': 'application/json' } } : {}),
  });
}
const id = (value: number | string) => ({ params: Promise.resolve({ id: String(value) }) });

function customAccess(userId: number, permissions: Permission[], scopeTags: string[] = []): Access {
  return {
    userId,
    role: 'viewer',
    isAdmin: false,
    customRole: { id: 1, name: 'Team' },
    permissions: new Set(permissions),
    scopeTags,
  };
}

async function seedHost(values: { id: number; domains: string[]; tags?: string[] }) {
  const now = new Date().toISOString();
  await ctx.db.insert(schema.proxyHosts).values({
    id: values.id,
    name: `host-${values.id}`,
    domains: JSON.stringify(values.domains),
    upstreams: '["backend:8080"]',
    tags: JSON.stringify(values.tags ?? []),
    createdAt: now,
    updatedAt: now,
  });
}

beforeEach(async () => {
  ctx.access = adminAccess(1);
  ctx.enabled = true;
  ctx.fail = false;
  ctx.seen = [];
  ctx.calls = [];
  ctx.rows = () => [];
  vi.mocked(logAuditEvent).mockClear();
  for (const table of [schema.analyticsSavedViews, schema.proxyHosts, schema.users]) {
    await ctx.db.delete(table).catch(() => {});
  }
  const now = new Date().toISOString();
  for (const [userId, role] of [[1, 'admin'], [2, 'viewer'], [3, 'viewer'], [4, 'viewer']] as const) {
    await ctx.db.insert(schema.users).values({
      id: userId, email: `user${userId}@example.com`, name: `User ${userId}`, role, provider: 'credentials', subject: `user${userId}`,
      status: 'active', createdAt: now, updatedAt: now,
    });
  }
  await seedHost({ id: 1, domains: ['app.example.com'], tags: ['team-a'] });
  await seedHost({ id: 2, domains: ['*.example.org'], tags: ['team-b'] });
  await seedHost({ id: 3, domains: ['client.example.net'] });
});

describe('permissions', () => {
  it('every analytics route needs analytics:read', async () => {
    ctx.access = customAccess(2, ['proxy_hosts:read']);
    const calls: Promise<Response>[] = [
      getQuery(req('/api/v1/analytics/query')),
      getTop(req('/api/v1/analytics/top')),
      getRequests(req('/api/v1/analytics/requests')),
      getHosts(req('/api/v1/analytics/hosts')),
      getHost(req('/api/v1/analytics/hosts/1'), id(1)),
      getSeries(req('/api/v1/analytics/security/series')),
      getRules(req('/api/v1/analytics/security/rules')),
      getSources(req('/api/v1/analytics/security/sources')),
      getEvents(req('/api/v1/analytics/security/events')),
      getSecurityHosts(req('/api/v1/analytics/security/hosts')),
      getSignals(req('/api/v1/analytics/signals')),
      listViews(req('/api/v1/analytics/views')),
      createView(req('/api/v1/analytics/views', { method: 'POST', body: { name: 'x' } })),
      getView(req('/api/v1/analytics/views/1'), id(1)),
      patchView(req('/api/v1/analytics/views/1', { method: 'PATCH', body: { name: 'x' } }), id(1)),
      deleteView(req('/api/v1/analytics/views/1', { method: 'DELETE' }), id(1)),
    ];
    for (const response of await Promise.all(calls)) expect(response.status).toBe(403);
    expect(ctx.calls).toHaveLength(0);
  });
});

describe('GET /api/v1/analytics/query', () => {
  it('runs the query with the filters bound as parameters', async () => {
    const hostile = "x' OR 1=1 --";
    const filters = encodeURIComponent(JSON.stringify([{ dim: 'path', op: 'is_not', value: hostile }, { dim: 'status', value: '5xx' }]));
    const response = await getQuery(req(`/api/v1/analytics/query?range=7d&metric=mitigated&filters=${filters}`));
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({ status: 'ok', metric: 'mitigated', groupBy: 'outcome', range: { preset: '7d', buckets: 56 } });
    expect(body.previous.available).toBe(true);
    expect(ctx.calls.length).toBeGreaterThan(0);
    for (const call of ctx.calls) {
      expect(call.query).not.toContain(hostile);
      expect(call.query_params).toMatchObject({ f0: hostile, f1: 5 });
      expect(call.query_params.p_scope).toBeUndefined();
    }
  });

  it.each([
    ['range=5m'],
    ['from=10'],
    ['metric=sum(bytes_sent)'],
    ['groupBy=uri'],
    ['topHosts=0'],
    [`filters=${encodeURIComponent('[{"dim":"client_ip","value":"192.0.2.1"}]')}`],
    ['filters=not-json'],
  ])('answers 400 for %s without querying ClickHouse', async (query) => {
    const response = await getQuery(req(`/api/v1/analytics/query?${query}`));
    expect(response.status).toBe(400);
    expect(ctx.calls).toHaveLength(0);
  });

  it('says when analytics is off or ClickHouse does not answer', async () => {
    ctx.enabled = false;
    expect(await (await getQuery(req('/api/v1/analytics/query'))).json()).toMatchObject({ status: 'disabled', series: [] });
    ctx.enabled = true;
    ctx.fail = true;
    const response = await getQuery(req('/api/v1/analytics/query?range=30d'));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: 'unavailable', previous: { available: false, reason: 'retention' } });
  });
});

describe('top, requests and security lists', () => {
  it('validate their parameters', async () => {
    expect((await getTop(req('/api/v1/analytics/top?dimensions=host,uri'))).status).toBe(400);
    expect((await getTop(req('/api/v1/analytics/top?limit=1000'))).status).toBe(400);
    expect((await getRequests(req('/api/v1/analytics/requests?limit=0'))).status).toBe(400);
    expect((await getRequests(req('/api/v1/analytics/requests?offset=-1'))).status).toBe(400);
    expect((await getEvents(req('/api/v1/analytics/security/events?kind=waf,blocked'))).status).toBe(400);
    expect((await getEvents(req('/api/v1/analytics/security/events?limit=501'))).status).toBe(400);
    expect((await getRules(req('/api/v1/analytics/security/rules?limit=abc'))).status).toBe(400);
    expect(ctx.calls).toHaveLength(0);
  });

  it('answer with their data', async () => {
    ctx.rows = (query) => {
      if (query.includes('count() AS total')) return [{ total: '10', d0: '2' }];
      if (query.includes('GROUP BY value')) return [{ value: 'app.example.com', c: '8', m: '2' }];
      if (query.includes('ORDER BY ts DESC')) {
        return [{ t: 1_791_000_000, o: 'waf', method: 'GET', host: 'app.example.com', path: '/.env', status: 403, country: 'NL', asn: 64500, as_org: 'Example', client_ip: '192.0.2.1', ua: 'curl 8.5.0', duration_ms: 3, bytes_sent: 9, waf_rule_id: 930130 }];
      }
      return [];
    };
    const top = await (await getTop(req('/api/v1/analytics/top?dimensions=host'))).json();
    expect(top).toMatchObject({ status: 'ok', total: 10, dimensions: [{ dimension: 'host', distinct: 2, rows: [{ value: 'app.example.com', count: 8, share: 0.8, mitigated: 2, mitigatedShare: 0.25 }] }] });
    const requests = await (await getRequests(req('/api/v1/analytics/requests?limit=5'))).json();
    expect(requests.requests[0]).toMatchObject({ outcome: 'waf', path: '/.env', wafRuleId: 930130, asOrg: 'Example' });
    for (const route of [getSeries, getRules, getSources, getEvents, getSecurityHosts]) {
      const response = await route(req('/api/v1/analytics/security/x?range=24h'));
      expect(response.status).toBe(200);
      expect((await response.json()).status).toBe('ok');
    }
    const signals = await (await getSignals(req('/api/v1/analytics/signals'))).json();
    expect(signals).toMatchObject({ status: 'ok', errorBursts: [], mitigationSpikes: [], blockedConcentrations: [] });
  });

  it('never return raw WAF audit records', async () => {
    ctx.rows = () => [
      { t: 1_791_000_000, kind: 'waf', blk: 1, host: 'app.example.com', method: 'GET', path: '/', client_ip: '192.0.2.1', country: 'NL', rid: 920450, message: 'm', sev: 'critical', code: 0, eid: 'tx-1' },
      { t: 1_790_999_000, kind: 'geo', blk: 1, host: 'app.example.com', method: 'GET', path: '/', client_ip: '192.0.2.2', country: 'DE', rid: -1, message: '', sev: '', code: 403, eid: '' },
    ];
    const body = await (await getEvents(req('/api/v1/analytics/security/events?includeRaw=true'))).json();
    expect(body.events[0]).toEqual({
      ts: 1_791_000_000, kind: 'waf', eventId: 'tx-1', blocked: true, host: 'app.example.com', method: 'GET', path: '/', ip: '192.0.2.1',
      country: 'NL', ruleId: 920450, message: 'm', severity: 'critical', status: 0,
    });
    expect(body.events[1]).toMatchObject({ kind: 'geo', eventId: null, ruleId: null, status: 403 });
    expect(ctx.calls.every((call) => !call.query.includes('raw_data'))).toBe(true);
  });

  it('filter the events by host, rule and address with bound parameters', async () => {
    const hostile = "x' OR 1=1 --";
    const filters = encodeURIComponent(
      JSON.stringify([
        { dim: 'host', op: 'is', value: 'App.Example.com:443' },
        { dim: 'waf_rule', op: 'is', value: '930130' },
        { dim: 'ip', op: 'is_not', value: '192.0.2.9' },
        { dim: 'path', op: 'is', value: hostile },
      ])
    );
    const response = await getEvents(req(`/api/v1/analytics/security/events?kind=waf,geo&filters=${filters}`));
    expect(response.status).toBe(200);
    expect(ctx.calls).toHaveLength(1);
    const [call] = ctx.calls;
    expect(call.query).not.toContain(hostile);
    expect(call.query_params).toMatchObject({ sf0: 'app.example.com', sf1: 930130, sf2: '192.0.2.9', sf3: hostile, p_kinds: ['geo'] });
    // The WAF side compares the rule; the other side has no rule, so a rule filter leaves it out.
    const [waf, traffic] = call.query.split('UNION ALL');
    expect(waf).toContain('toUInt32(ifNull(rule_id, 0)) = {sf1:UInt32}');
    expect(traffic).toContain('(0)');
    expect(traffic).not.toContain('rule_id');
    expect(call.query).toContain('NOT ((client_ip) = {sf2:String})');
  });

  it.each([
    [`filters=${encodeURIComponent('[{"dim":"asn","value":"13335"}]')}`],
    [`filters=${encodeURIComponent('[{"dim":"user_agent","value":"curl"}]')}`],
    [`filters=${encodeURIComponent('[{"dim":"ip","value":"not-an-ip"}]')}`],
    [`filters=${encodeURIComponent('[{"dim":"waf_rule","value":"93x"}]')}`],
    ['filters=nope'],
  ])('answer 400 for event filters %s without querying', async (query) => {
    expect((await getEvents(req(`/api/v1/analytics/security/events?${query}`))).status).toBe(400);
    expect(ctx.calls).toHaveLength(0);
  });

  it('rank the most targeted hosts with the proxy host serving each', async () => {
    ctx.rows = (query) => {
      if (query.includes('GROUP BY name')) {
        return [
          { name: 'app.example.com', events: '12', waf: '10', other: '2' },
          { name: 'x.example.org', events: '3', waf: '0', other: '3' },
          { name: 'unknown.example.net', events: '1', waf: '1', other: '0' },
        ];
      }
      return [{ n: '16' }];
    };
    const body = await (await getSecurityHosts(req('/api/v1/analytics/security/hosts?range=24h&limit=3'))).json();
    expect(body).toMatchObject({ status: 'ok', totals: { events: 16 } });
    expect(body.hosts).toEqual([
      { host: 'app.example.com', events: 12, wafEvents: 10, otherMitigated: 2, proxyHostId: 1 },
      { host: 'x.example.org', events: 3, wafEvents: 0, otherMitigated: 3, proxyHostId: 2 },
      { host: 'unknown.example.net', events: 1, wafEvents: 1, otherMitigated: 0, proxyHostId: null },
    ]);
    expect((await getSecurityHosts(req('/api/v1/analytics/security/hosts?limit=0'))).status).toBe(400);
  });

  it('explain the peak bucket of the series: busiest source, host and rule', async () => {
    ctx.rows = (query) => {
      if (query.includes('GROUP BY b, o')) return [{ b: '3', o: 'waf', c: '40' }, { b: '3', o: 'geo', c: '5' }, { b: '1', o: 'access', c: '2' }];
      if (query.includes('countIf(ts >= toDateTime({p_from:UInt32})) AS requests')) return [{ requests: '1000', mitigated: '47', previous: '20' }];
      if (query.includes('uniq(client_ip) AS n')) return [{ n: '7' }];
      if (query.includes('GROUP BY client_ip')) return [{ client_ip: '198.51.100.7', country: 'NL', n: '30' }];
      if (query.includes('GROUP BY name')) return [{ name: 'app.example.com', n: '41' }];
      if (query.includes('GROUP BY rule_id')) return [{ rule_id: '930130', n: '25' }];
      if (query.includes('p_peak_rule')) return [{ message: 'Restricted file access attempt' }];
      return [];
    };
    const body = await (await getSeries(req('/api/v1/analytics/security/series?range=24h'))).json();
    expect(body.peak).toMatchObject({
      index: 3,
      value: 45,
      bySource: { waf: 40, geo: 5 },
      top: {
        addresses: 7,
        source: { ip: '198.51.100.7', country: 'NL', count: 30 },
        host: { name: 'app.example.com', count: 41 },
        rule: { ruleId: 930130, message: 'Restricted file access attempt', count: 25 },
      },
    });
    const bucketCalls = ctx.calls.filter((call) => call.query_params.p_to === body.peak.ts + body.range.step);
    expect(bucketCalls).toHaveLength(5);
    for (const call of bucketCalls.filter((c) => !c.query.includes('p_peak_rule'))) {
      expect(call.query).toContain('FROM traffic_events WHERE');
      expect(call.query).not.toContain('UNION ALL');
    }
    for (const call of bucketCalls) expect(call.query_params.p_from).toBe(body.peak.ts);
  });
});

describe('peak population (issue 398)', () => {
  it('excludes two DetectionOnly matches and uses one stopped access event for every attribution', async () => {
    ctx.rows = (sql) => {
      if (sql.includes('GROUP BY b, o')) return [{ b: 0, o: 'waf', c: 1 }];
      if (sql.includes('AS requests')) return [{ requests: 3, mitigated: 1, previous: 0 }];
      if (sql.includes('FROM waf_events') && !sql.includes('p_peak_rule')) throw new Error('wrong population');
      if (sql.includes('uniq(client_ip)')) return [{ n: 1 }];
      if (sql.includes('GROUP BY client_ip')) return [{ client_ip: '192.0.2.1', country: 'XX', n: 1 }];
      if (sql.includes('GROUP BY name')) return [{ name: 'blocked.example', n: 1 }];
      if (sql.includes('GROUP BY rule_id')) return [{ rule_id: 941100, n: 1 }];
      if (sql.includes('p_peak_rule')) return [{ message: 'XSS' }];
      return [];
    };
    const body = await (await getSeries(req('/api/v1/analytics/security/series?range=1h'))).json();
    expect(body.status).toBe('ok');
    expect(body.peak).toMatchObject({ value: 1, top: { addresses: 1, source: { count: 1 }, host: { count: 1 }, rule: { ruleId: 941100, count: 1 } } });
    const rule = ctx.calls.find((c) => c.query.includes('waf_rule_id AS rule_id'))!;
    expect(rule.query).toContain('waf_rule_id > 0');
    expect(rule.query).toContain("= 'waf'");
  });
});

describe('per-host summaries', () => {
  it("cover the proxy hosts a tag-scoped role reaches, with their traffic", async () => {
    ctx.access = customAccess(2, ['analytics:read', 'proxy_hosts:read'], ['team-b']);
    ctx.rows = () => [
      { name: 'a.example.org', b: '0', requests: '5', e5: '1', m: '2', bytes: '100' },
      { name: 'deep.a.example.org', b: '0', requests: '50', e5: '0', m: '0', bytes: '1' },
      { name: 'app.example.com', b: '0', requests: '9', e5: '0', m: '0', bytes: '1' },
    ];
    const body = await (await getHosts(req('/api/v1/analytics/hosts?range=24h'))).json();
    expect(body.status).toBe('ok');
    expect(body.hosts).toHaveLength(1);
    expect(body.hosts[0]).toMatchObject({ proxyHostId: 2, requests: 5, errors5xx: 1, errorRate5xx: 0.2, mitigated: 2, bytes: 100 });
    expect(body.hosts[0].sparkline).toHaveLength(24);
    expect(ctx.calls[0].query_params).toMatchObject({ p_dom_suffix: ['.example.org'] });
    expect(ctx.calls[0].query_params.p_dom_exact).toBeUndefined();
  });

  it('can be limited to some ids and refuses bad ones', async () => {
    const body = await (await getHosts(req('/api/v1/analytics/hosts?ids=1,3'))).json();
    expect(body.hosts.map((host: { proxyHostId: number }) => host.proxyHostId).sort()).toEqual([1, 3]);
    expect((await getHosts(req('/api/v1/analytics/hosts?ids=1,x'))).status).toBe(400);
  });

  it('answer 404 for a host outside the scope, as for a missing one', async () => {
    ctx.access = customAccess(2, ['analytics:read'], ['team-b']);
    expect((await getHost(req('/api/v1/analytics/hosts/1'), id(1))).status).toBe(404);
    expect((await getHost(req('/api/v1/analytics/hosts/99'), id(99))).status).toBe(404);
    expect((await getHost(req('/api/v1/analytics/hosts/abc'), id('abc'))).status).toBe(400);
    const own = await getHost(req('/api/v1/analytics/hosts/2?range=1h'), id(2));
    expect(own.status).toBe(200);
    expect(await own.json()).toMatchObject({ status: 'ok', proxyHostId: 2, range: { preset: '1h', buckets: 60 } });
  });

  it("leave another host's exact domain out of a wildcard host's detail", async () => {
    await seedHost({ id: 4, domains: ['shop.example.org'] });
    await getHost(req('/api/v1/analytics/hosts/2'), id(2));
    expect(ctx.calls[0].query_params).toMatchObject({ p_dom_suffix: ['.example.org'], p_dom_exclude: ['shop.example.org'] });
  });
});

describe('saved views', () => {
  const view = { name: 'Errors on the API', range: '7d', metric: 'errors', groupBy: 'status', filters: [{ dim: 'host', value: 'app.example.com' }] };

  it('are created, read, changed and deleted by their owner, with audit events', async () => {
    const created = await createView(req('/api/v1/analytics/views', { method: 'POST', body: view }));
    expect(created.status).toBe(201);
    const body = await created.json();
    expect(body).toMatchObject({ name: 'Errors on the API', shared: false, range: { preset: '7d' }, metric: 'errors', groupBy: 'status', owned: true, ownerName: 'User 1' });
    expect(body.filters).toEqual([{ dim: 'host', op: 'is', value: 'app.example.com' }]);
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'create', entityType: 'analytics_view', entityId: body.id, userId: 1 }));

    const changed = await patchView(req(`/api/v1/analytics/views/${body.id}`, { method: 'PATCH', body: { shared: true, range: { from: 1_790_000_000, to: 1_790_086_400 } } }), id(body.id));
    expect(changed.status).toBe(200);
    expect(await changed.json()).toMatchObject({ shared: true, range: { from: 1_790_000_000, to: 1_790_086_400 } });
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'update', entityType: 'analytics_view', data: { changed: ['shared', 'range'] } }));

    expect((await getView(req(`/api/v1/analytics/views/${body.id}`), id(body.id))).status).toBe(200);
    expect((await deleteView(req(`/api/v1/analytics/views/${body.id}`, { method: 'DELETE' }), id(body.id))).status).toBe(200);
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'delete', entityType: 'analytics_view', entityId: body.id }));
    expect((await getView(req(`/api/v1/analytics/views/${body.id}`), id(body.id))).status).toBe(404);
  });

  it.each([
    [{ name: '' }],
    [{ name: 'x'.repeat(101) }],
    [{ name: 'x', range: '2d' }],
    [{ name: 'x', range: { from: 10, to: 5 } }],
    [{ name: 'x', metric: 'count()' }],
    [{ name: 'x', groupBy: 'uri' }],
    [{ name: 'x', shared: 'yes' }],
    [{ name: 'x', filters: [{ dim: 'uri', value: '/' }] }],
    [[1, 2]],
  ])('refuses %j', async (input) => {
    const response = await createView(req('/api/v1/analytics/views', { method: 'POST', body: input }));
    expect(response.status).toBe(400);
  });

  it('are shared with every analytics reader, and only the owner changes them', async () => {
    const shared = await (await createView(req('/api/v1/analytics/views', { method: 'POST', body: { ...view, name: 'Shared', shared: true } }))).json();
    const priv = await (await createView(req('/api/v1/analytics/views', { method: 'POST', body: { ...view, name: 'Private' } }))).json();

    // Another analytics reader sees the shared view only.
    ctx.access = customAccess(2, ['analytics:read']);
    const listed = await (await listViews(req('/api/v1/analytics/views'))).json();
    expect(listed.map((v: { name: string; owned: boolean }) => [v.name, v.owned])).toEqual([['Shared', false]]);
    expect((await getView(req(`/api/v1/analytics/views/${priv.id}`), id(priv.id))).status).toBe(404);
    expect((await patchView(req(`/api/v1/analytics/views/${priv.id}`, { method: 'PATCH', body: { name: 'x' } }), id(priv.id))).status).toBe(404);
    expect((await patchView(req(`/api/v1/analytics/views/${shared.id}`, { method: 'PATCH', body: { name: 'Mine now' } }), id(shared.id))).status).toBe(403);
    expect((await deleteView(req(`/api/v1/analytics/views/${shared.id}`, { method: 'DELETE' }), id(shared.id))).status).toBe(403);

    // A view saved with only a name takes the defaults.
    ctx.access = customAccess(3, ['analytics:read']);
    const defaults = await (await createView(req('/api/v1/analytics/views', { method: 'POST', body: { name: 'Client view', shared: true } }))).json();
    expect(defaults).toMatchObject({ range: { preset: '24h' }, metric: 'requests', groupBy: null, filters: [] });

    // ...and an administrator may delete someone else's shared view, never see their private ones.
    ctx.access = adminAccess(4);
    expect((await deleteView(req(`/api/v1/analytics/views/${shared.id}`, { method: 'DELETE' }), id(shared.id))).status).toBe(200);
    expect((await deleteView(req(`/api/v1/analytics/views/${priv.id}`, { method: 'DELETE' }), id(priv.id))).status).toBe(404);
  });

  it('are deleted with their owner', async () => {
    ctx.access = customAccess(2, ['analytics:read']);
    await createView(req('/api/v1/analytics/views', { method: 'POST', body: { name: 'Doomed', shared: true } }));
    await deleteUser(2);
    ctx.access = adminAccess(1);
    expect(await (await listViews(req('/api/v1/analytics/views'))).json()).toEqual([]);
  });
});

describe('OpenAPI', () => {
  it('documents every analytics endpoint and its references resolve', async () => {
    const doc = await (await getOpenApi(req('/api/v1/openapi.json'))).json();
    const expected: Record<string, string[]> = {
      '/api/v1/analytics/query': ['get'],
      '/api/v1/analytics/top': ['get'],
      '/api/v1/analytics/requests': ['get'],
      '/api/v1/analytics/hosts': ['get'],
      '/api/v1/analytics/hosts/{id}': ['get'],
      '/api/v1/analytics/security/series': ['get'],
      '/api/v1/analytics/security/rules': ['get'],
      '/api/v1/analytics/security/sources': ['get'],
      '/api/v1/analytics/security/events': ['get'],
      '/api/v1/analytics/security/hosts': ['get'],
      '/api/v1/analytics/signals': ['get'],
      '/api/v1/analytics/views': ['get', 'post'],
      '/api/v1/analytics/views/{id}': ['delete', 'get', 'patch'],
    };
    for (const [path, methods] of Object.entries(expected)) {
      expect(Object.keys(doc.paths[path]).sort(), path).toEqual(methods);
      for (const method of methods) {
        expect(doc.paths[path][method].tags).toEqual(['Analytics']);
        expect(doc.paths[path][method].description).toContain('analytics:read');
      }
    }
    expect(doc.tags.map((tag: { name: string }) => tag.name)).toContain('Analytics');
    const documented = JSON.stringify([
      ...Object.keys(expected).map((path) => doc.paths[path]),
      ...Object.entries(doc.components.schemas).filter(([name]) => name.startsWith('Analytics')).map(([, schema]) => schema),
    ]);
    const refs = documented.match(/"\$ref":"#\/components\/[^"]+"/g) ?? [];
    expect(refs.length).toBeGreaterThan(20);
    for (const ref of new Set(refs)) {
      const path = JSON.parse(`{${ref}}`).$ref.slice('#/'.length).split('/');
      expect(path.reduce((node: any, key: string) => node?.[key], doc), ref).toBeDefined();
    }
  });
});
