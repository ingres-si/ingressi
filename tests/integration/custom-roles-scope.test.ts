/**
 * Tag scopes of custom roles on proxy hosts, L4 hosts and certificates,
 * through the REST API (real API tokens and guards), the dashboard server
 * actions and the pages (real requirePermission with a mocked session), and
 * the limits on every non-administrator (raw Caddy JSON, the admin API port,
 * references the caller cannot read).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import * as schema from '../../src/lib/db/schema';
import { apiRequest, idParams, insertRole, insertToken, insertUser, json, nowIso } from '../helpers/custom-roles';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb, sessionUserId: 0 }));

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));
vi.mock('@/src/lib/auth', async (importOriginal) => importOriginal());
vi.mock('@/src/lib/auth-server', () => ({
  getAuth: () => ({
    api: { getSession: async () => ({ user: { id: ctx.sessionUserId }, session: { id: 1, createdAt: new Date() } }) },
  }),
  reloadOAuthProviders: async () => {},
}));
vi.mock('next/headers', () => ({ headers: async () => new Headers() }));
vi.mock('next/navigation', () => ({ redirect: (url: string) => { throw new Error(`REDIRECT:${url}`); } }));
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));

import * as hostsRoute from '@/app/api/v1/proxy-hosts/route';
import * as hostRoute from '@/app/api/v1/proxy-hosts/[id]/route';
import * as faRoute from '@/app/api/v1/proxy-hosts/[id]/forward-auth-access/route';
import * as rulesRoute from '@/app/api/v1/proxy-hosts/[id]/mtls-access-rules/route';
import * as l4sRoute from '@/app/api/v1/l4-proxy-hosts/route';
import * as l4Route from '@/app/api/v1/l4-proxy-hosts/[id]/route';
import * as certsRoute from '@/app/api/v1/certificates/route';
import * as certRoute from '@/app/api/v1/certificates/[id]/route';
import * as caRoute from '@/app/api/v1/ca-certificates/route';
import ProxyHostsPage from '@/app/(dashboard)/proxy-hosts/page';
import L4ProxyHostsPage from '@/app/(dashboard)/l4-proxy-hosts/page';
import {
  deleteProxyHostAction,
  toggleProxyHostAction,
  updateProxyHostAction,
  createProxyHostAction,
} from '@/app/(dashboard)/proxy-hosts/actions';
import { deleteL4ProxyHostAction } from '@/app/(dashboard)/l4-proxy-hosts/actions';
import { deleteCertificateAction } from '@/app/(dashboard)/certificates/actions';
import { createUserAction, deleteUserAction, updateUserRoleAction, updateUserStatusAction } from '@/app/(dashboard)/users/actions';
import { deleteRoleAction, saveRoleAction } from '@/ee/custom-roles/ui/actions';
import UsersPage from '@/app/(dashboard)/users/page';
import { first } from '@/src/lib/db/ops';
import { assertSettingsWriteAllowed } from '@/src/lib/access-scope';
import { adminAccess, type Access } from '@/src/lib/permissions';

const ADMIN = 1;
const TEAM_A = 2; // scoped to team-a
const OPERATOR = 3; // same permissions, no scope

let tokens: { admin: string; teamA: string; operator: string };
let hosts: { a: number; b: number; ab: number; untagged: number };
let l4: { a: number; b: number };
let certs: { a: number; b: number; shared: number };

async function host(name: string, domains: string[], tags: string[], certificateId: number | null = null) {
  const now = nowIso();
  return (await first(ctx.db.insert(schema.proxyHosts).values({
    name, domains: JSON.stringify(domains), upstreams: '["backend:8080"]', certificateId, tags: JSON.stringify(tags),
    createdAt: now, updatedAt: now,
  }).returning()))!.id;
}

async function l4Host(name: string, listenAddress: string, tags: string[]) {
  const now = nowIso();
  return (await first(ctx.db.insert(schema.l4ProxyHosts).values({
    name, protocol: 'tcp', listenAddress, upstreams: '["db:5432"]', tags: JSON.stringify(tags), createdAt: now, updatedAt: now,
  }).returning()))!.id;
}

async function certificate(name: string) {
  const now = nowIso();
  return (await first(ctx.db.insert(schema.certificates).values({
    name, type: 'managed', domainNames: '["x.example.com"]', createdAt: now, updatedAt: now,
  }).returning()))!.id;
}

async function storedTags(id: number): Promise<string[]> {
  return JSON.parse((await first(ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, id)).limit(1)))!.tags);
}

const PERMISSIONS = [
  'proxy_hosts:read', 'proxy_hosts:write', 'l4_proxy_hosts:read', 'l4_proxy_hosts:write',
  'certificates:read', 'certificates:write',
];

beforeEach(async () => {
  ctx.db = createTestDb();
  await insertRole(ctx.db, 1, PERMISSIONS, ['team-a'], 'Team A');
  await insertRole(ctx.db, 2, PERMISSIONS, [], 'Operators');
  await insertUser(ctx.db, ADMIN, 'admin');
  await insertUser(ctx.db, TEAM_A, 'viewer', 1);
  await insertUser(ctx.db, OPERATOR, 'viewer', 2);
  tokens = { admin: await insertToken(ctx.db, ADMIN), teamA: await insertToken(ctx.db, TEAM_A), operator: await insertToken(ctx.db, OPERATOR) };
  certs = { a: await certificate('A cert'), b: await certificate('B cert'), shared: await certificate('Shared cert') };
  hosts = {
    a: await host('A', ['a.example.com'], ['team-a'], certs.a),
    b: await host('B', ['b.example.com'], ['team-b'], certs.b),
    ab: await host('AB', ['ab.example.com'], ['team-a', 'team-b'], certs.shared),
    untagged: await host('Untagged', ['u.example.com'], [], certs.shared),
  };
  l4 = { a: await l4Host('A db', ':5432', ['team-a']), b: await l4Host('B db', ':6432', ['team-b']) };
});

const newHost = (extra: object = {}) => ({ name: 'New', domains: ['new.example.com'], upstreams: ['backend:80'], ...extra });

describe('proxy hosts', () => {
  it('lists only the hosts with one of the role\'s tags', async () => {
    const list = await json(await hostsRoute.GET(apiRequest('GET', '/api/v1/proxy-hosts', tokens.teamA)));
    expect(list.map((h: { name: string }) => h.name).sort()).toEqual(['A', 'AB']);
    const all = await json(await hostsRoute.GET(apiRequest('GET', '/api/v1/proxy-hosts', tokens.operator)));
    expect(all).toHaveLength(4);
    expect(all.find((h: { name: string }) => h.name === 'AB').tags).toEqual(['team-a', 'team-b']);
  });

  it('answers 404 for a host outside the scope, as for a missing one', async () => {
    expect((await hostRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(hosts.b))).status).toBe(404);
    expect((await hostRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(hosts.untagged))).status).toBe(404);
    expect((await hostRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(hosts.a))).status).toBe(200);
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { name: 'Taken' }), idParams(hosts.b))).status).toBe(404);
    expect((await hostRoute.DELETE(apiRequest('DELETE', '/x', tokens.teamA), idParams(hosts.b))).status).toBe(404);
    expect((await faRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(hosts.b))).status).toBe(404);
    expect((await rulesRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(hosts.b))).status).toBe(404);
    expect((await first(ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, hosts.b)).limit(1)))!.name).toBe('B');
    // In scope: works.
    expect((await hostRoute.DELETE(apiRequest('DELETE', '/x', tokens.teamA), idParams(hosts.a))).status).toBe(200);
  });

  it('needs one of the role\'s tags to create a host, and only the role\'s tags', async () => {
    const missing = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost()));
    expect(missing.status).toBe(400);
    expect((await json(missing)).error).toMatch(/at least one of your role's tags: team-a/);
    expect((await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['team-b'] })))).status).toBe(403);
    expect((await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['team-a', 'prod'] })))).status).toBe(403);
    const created = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['Team-A'] })));
    expect(created.status).toBe(201);
    expect((await json(created)).tags).toEqual(['team-a']);
    // Without a scope, tags are free.
    const free = await hostsRoute.POST(apiRequest('POST', '/x', tokens.operator, newHost({ domains: ['free.example.com'], tags: ['prod', 'eu'] })));
    expect(free.status).toBe(201);
    expect((await json(free)).tags).toEqual(['eu', 'prod']);
  });

  it('keeps tags outside the scope and refuses taking the last scope tag away', async () => {
    const response = await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { tags: ['team-a'] }), idParams(hosts.ab));
    expect(response.status).toBe(200);
    expect(await storedTags(hosts.ab)).toEqual(['team-a', 'team-b']);
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { tags: [] }), idParams(hosts.a))).status).toBe(400);
    expect(await storedTags(hosts.a)).toEqual(['team-a']);
    // Other changes leave the tags alone.
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { name: 'Renamed' }), idParams(hosts.a))).status).toBe(200);
    expect(await storedTags(hosts.a)).toEqual(['team-a']);
  });

  it('refuses domains served by a host outside the scope, wildcards included', async () => {
    for (const domains of [['b.example.com'], ['*.example.com'], ['u.example.com']]) {
      const response = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ domains, tags: ['team-a'] })));
      expect(response.status, domains.join()).toBe(403);
      expect((await json(response)).error).toMatch(/outside your role's scope/);
    }
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { domains: ['b.example.com'] }), idParams(hosts.a))).status).toBe(403);
    // A domain of an in-scope host is the team's own business.
    expect((await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ domains: ['ab.example.com'], tags: ['team-a'] })))).status).toBe(201);
  });

  it('refuses raw Caddy JSON and the admin API port to every non-administrator', async () => {
    for (const token of [tokens.teamA, tokens.operator]) {
      const json1 = await hostsRoute.POST(apiRequest('POST', '/x', token, newHost({ tags: ['team-a'], customReverseProxyJson: '{"handler":"static_response"}' })));
      expect(json1.status).toBe(403);
      const port = await hostsRoute.POST(apiRequest('POST', '/x', token, newHost({ tags: ['team-a'], upstreams: ['http://caddy:2019'] })));
      expect(port.status).toBe(403);
      expect((await json(port)).error).toMatch(/port 2019/);
      const location = await hostsRoute.POST(apiRequest('POST', '/x', token, newHost({
        tags: ['team-a'], locationRules: [{ path: '/api/*', upstreams: ['localhost:2019'] }],
      })));
      expect(location.status).toBe(403);
    }
    const admin = await hostsRoute.POST(apiRequest('POST', '/x', tokens.admin, newHost({ customReverseProxyJson: '{"headers":{}}' })));
    expect(admin.status).toBe(201);
  });

  it('refuses every address Caddy would dial on the admin API port, however it is written', async () => {
    const refused: Array<[string, object]> = [
      ['a port range', { upstreams: ['localhost:2019-2019'] }],
      ['a query string', { upstreams: ['http://localhost:2019?x'] }],
      ['a fragment', { upstreams: ['http://localhost:2019#x'] }],
      ['a placeholder port', { upstreams: ['localhost:{http.request.header.p}'] }],
      ['a placeholder address', { upstreams: ['{http.request.header.u}'] }],
      ['an IPv6 location upstream', { locationRules: [{ path: '/api/*', upstreams: ['[::1]:2019'] }] }],
      ['a unix-socket upstream', { upstreams: ['unix//run/caddy-admin/admin.sock'] }],
      ['a unix-socket location upstream', { locationRules: [{ path: '/api/*', upstreams: ['unix//tmp/x.sock'] }] }],
      ['an fd upstream', { upstreams: ['fd/3'] }],
      ['the Authentik outpost', { authentik: { enabled: true, outpostDomain: 'config', outpostUpstream: 'http://localhost:2019' } }],
      ['the Authentik outpost with a path', { authentik: { enabled: true, outpostDomain: 'config', outpostUpstream: 'http://caddy:2019/' } }],
      ['the forward-auth server', { forwardAuth: { enabled: true, provider: 'custom', authUpstream: 'http://localhost:2019', authEndpoint: '/config/' } }],
      ['an active health check', { loadBalancer: { enabled: true, activeHealthCheck: { enabled: true, port: 2019 } } }],
      ['a location rule\'s active health check', { locationRules: [{ path: '/x/*', upstreams: ['backend:8080'], loadBalancer: { enabled: true, activeHealthCheck: { enabled: true, port: 2019 } } }] }],
    ];
    for (const token of [tokens.teamA, tokens.operator]) {
      for (const [label, extra] of refused) {
        const response = await hostsRoute.POST(apiRequest('POST', '/x', token, newHost({ tags: ['team-a'], ...extra })));
        expect(response.status, label).toBe(403);
      }
      const update = await hostRoute.PUT(apiRequest('PUT', '/x', token, {
        authentik: { enabled: true, outpostDomain: 'config', outpostUpstream: 'http://localhost:2019' },
      }), idParams(hosts.a));
      expect(update.status).toBe(403);
    }
    // Placeholders never reach the Authentik outpost path (it also forms the forward-auth URI).
    const stripped = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({
      tags: ['team-a'], domains: ['strip.example.com'],
      authentik: { enabled: true, outpostDomain: 'o{file./etc/hostname}', outpostUpstream: 'http://authentik-outpost:9000', authEndpoint: '{x}' },
    })));
    expect(stripped.status).toBe(201);
    expect(JSON.stringify(await json(stripped))).not.toContain('{file.');
    // Ordinary addresses still work.
    const outpost = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({
      tags: ['team-a'], upstreams: ['http://backend:8080/app'],
      authentik: { enabled: true, outpostDomain: 'outpost.goauthentik.io', outpostUpstream: 'http://authentik-outpost:9000' },
    })));
    expect(outpost.status).toBe(201);
    // Administrators are not limited.
    const admin = await hostsRoute.POST(apiRequest('POST', '/x', tokens.admin, newHost({
      authentik: { enabled: true, outpostDomain: 'config', outpostUpstream: 'http://localhost:2019' },
    })));
    expect(admin.status).toBe(201);
  });

  it('lets a host keep what an administrator set on it, and nothing more', async () => {
    // An administrator's host in the scope: a placeholder upstream, a socket in a location rule, the admin port as outpost.
    const special = await hostsRoute.POST(apiRequest('POST', '/x', tokens.admin, newHost({
      tags: ['team-a'],
      domains: ['special.example.com'],
      upstreams: ['{env.BACKEND}:8080'],
      locationRules: [{ path: '/sock/*', upstreams: ['unix//run/app.sock'] }],
      authentik: { enabled: true, outpostDomain: 'outpost.example.com', outpostUpstream: 'http://localhost:2019' },
    })));
    expect(special.status, await special.clone().text()).toBe(201);
    const id = (await json(special)).id as number;
    const put = async (body: object) => (await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, body), idParams(id))).status;

    // The editor sends every field back with the one that changed.
    expect(await put({
      name: 'Renamed',
      upstreams: ['{env.BACKEND}:8080'],
      locationRules: [{ path: '/sock/*', upstreams: ['unix//run/app.sock'] }],
      authentik: { enabled: true, outpostDomain: 'outpost.example.com', outpostUpstream: 'http://localhost:2019' },
    })).toBe(200);

    // Another spelling is another value when Caddy would dial it differently
    // ("http://" in front turns the placeholder into a host name).
    expect(await put({ upstreams: ['http://{env.BACKEND}:8080'] })).toBe(403);
    expect(await put({ upstreams: ['https://{env.BACKEND}:8080'] })).toBe(403);

    // The same values anywhere else are still refused.
    expect(await put({ upstreams: ['{env.BACKEND}:8080', '{env.OTHER}:8080'] })).toBe(403);
    expect(await put({ upstreams: ['unix//run/app.sock'] })).toBe(403);
    expect(await put({ locationRules: [{ path: '/other/*', upstreams: ['unix//run/app.sock'] }] })).toBe(403);
    expect(await put({ locationRules: [{ path: '/sock/*', upstreams: ['{env.BACKEND}:8080'] }] })).toBe(403);
    expect(await put({ forwardAuth: { enabled: true, provider: 'custom', authUpstream: 'http://localhost:2019', authEndpoint: '/verify' } })).toBe(403);
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { upstreams: ['{env.BACKEND}:8080'] }), idParams(hosts.a))).status).toBe(403);
    expect((await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['team-a'], upstreams: ['{env.BACKEND}:8080'] })))).status).toBe(403);
  });

  it('lets nobody but an administrator add a destination to a host with custom Caddy JSON', async () => {
    // The JSON can carry what only Caddy can read (an {env.…} request header): whoever picks the upstream receives it.
    const created = await hostsRoute.POST(apiRequest('POST', '/x', tokens.admin, newHost({
      tags: ['team-a'],
      domains: ['json.example.com'],
      upstreams: ['backend:8080', 'backend2:8080'],
      locationRules: [{ path: '/api/*', upstreams: ['api:8080'] }],
      customReverseProxyJson: JSON.stringify({ headers: { request: { set: { 'X-Api-Key': ['{env.BACKEND_KEY}'] } } } }),
    })));
    expect(created.status, await created.clone().text()).toBe(201);
    const stored = await json(created);
    const id = stored.id as number;
    const put = async (token: string, body: object) => {
      const response = await hostRoute.PUT(apiRequest('PUT', '/x', token, body), idParams(id));
      return { status: response.status, error: ((await json(response)) as { error?: string }).error ?? '' };
    };
    const upstreams = stored.upstreams as string[];
    const rule = (stored.locationRules as { path: string; upstreams: string[] }[])[0];

    // Everything else, the same destinations in another order, and fewer of them.
    expect((await put(tokens.teamA, { name: 'Renamed', upstreams, locationRules: [rule] })).status).toBe(200);
    expect((await put(tokens.teamA, { upstreams: [...upstreams].reverse() })).status).toBe(200);
    expect((await put(tokens.teamA, { upstreams: [upstreams[0]], locationRules: [] })).status).toBe(200);

    // As the host editor sends them back: with "http://" where the stored upstream has no scheme, and the other way round.
    const flipped = (upstream: string) => (upstream.startsWith('http://') ? upstream.slice(7) : `http://${upstream}`);
    expect((await put(tokens.teamA, { upstreams: [flipped(upstreams[0])], locationRules: [] })).status).toBe(200);
    expect((await put(tokens.teamA, { upstreams: [upstreams[0]], locationRules: [] })).status).toBe(200);
    // Not the same upstream: TLS, another port, another host.
    for (const other of ['https://backend:8080', 'backend:8081', 'http://backend', 'http://user@collector.example.net:8080']) {
      expect((await put(tokens.teamA, { upstreams: [other] })).status, other).toBe(403);
    }

    // A new destination, wherever it goes.
    const refused = /Only administrators can add a destination/;
    for (const body of [
      { upstreams: [upstreams[0], 'collector.example.net:443'] },
      { upstreams: ['https://collector.example.net'] },
      { locationRules: [{ path: '/api/*', upstreams: ['collector.example.net:443'] }] },
      { locationRules: [{ path: '/new/*', upstreams: [upstreams[0]] }] },
      { authentik: { enabled: true, outpostDomain: 'outpost.example.com', outpostUpstream: 'http://collector.example.net:9000' } },
      { forwardAuth: { enabled: true, provider: 'custom', authUpstream: 'http://collector.example.net:9000', authEndpoint: '/verify' } },
      { upstreams: [7] },
    ]) {
      const answer = await put(tokens.teamA, body);
      expect(answer.status, JSON.stringify(body)).toBe(403);
      expect(answer.error, JSON.stringify(body)).toMatch(refused);
    }
    expect((await put(tokens.operator, { upstreams: ['collector.example.net:443'] })).status).toBe(403);

    // An administrator may, and a host without custom JSON is anybody's to point elsewhere.
    expect((await put(tokens.admin, { upstreams: ['elsewhere:8080'] })).status).toBe(200);
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { upstreams: ['elsewhere:8080'] }), idParams(hosts.a))).status).toBe(200);
  });

  it('needs waf:write to change a host\'s custom WAF directives', async () => {
    const RULE = 'SecRule REQUEST_URI "@beginsWith /internal" "id:9101,phase:1,deny,status:403"';
    const put = async (token: string, id: number, body: object) =>
      (await hostRoute.PUT(apiRequest('PUT', '/x', token, body), idParams(id))).status;

    // Without waf:write: the structured WAF settings of the host, yes; rule text, no.
    expect(await put(tokens.teamA, hosts.a, { waf: { enabled: true, mode: 'On' } })).toBe(200);
    expect(await put(tokens.teamA, hosts.a, { waf: { enabled: true, mode: 'On', custom_directives: RULE } })).toBe(403);
    expect(await put(tokens.teamA, hosts.a, { waf: { enabled: true, mode: 'On', custom_directives: 7 } })).toBe(403);
    expect((await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['team-a'], waf: { enabled: true, custom_directives: RULE } })))).status).toBe(403);
    expect((await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['team-a'], waf: { enabled: true, custom_directives: '' } })))).status).toBe(201);

    // What an administrator wrote stays when the host is saved with it, and cannot be changed or removed.
    expect(await put(tokens.admin, hosts.a, { waf: { enabled: true, mode: 'On', custom_directives: RULE } })).toBe(200);
    expect(await put(tokens.teamA, hosts.a, { name: 'Renamed', waf: { enabled: true, mode: 'DetectionOnly', custom_directives: `${RULE}\r\n` } })).toBe(200);
    expect(await put(tokens.teamA, hosts.a, { name: 'Renamed again' })).toBe(200);
    expect(await put(tokens.teamA, hosts.a, { waf: { enabled: true, mode: 'On', custom_directives: `${RULE}\nSecRuleEngine Off` } })).toBe(403);
    expect(await put(tokens.teamA, hosts.a, { waf: { enabled: true, mode: 'On', custom_directives: '' } })).toBe(403);
    expect(await put(tokens.teamA, hosts.a, { waf: { enabled: true, mode: 'On' } })).toBe(403);
    expect(await put(tokens.teamA, hosts.a, { waf: null })).toBe(403);

    // With waf:write as well.
    await insertRole(ctx.db, 3, [...PERMISSIONS, 'waf:read', 'waf:write'], ['team-a'], 'Team A with WAF');
    const WAF_USER = 77;
    await insertUser(ctx.db, WAF_USER, 'viewer', 3);
    const wafToken = await insertToken(ctx.db, WAF_USER);
    expect(await put(wafToken, hosts.a, { waf: { enabled: true, mode: 'On', custom_directives: `${RULE}\nSecRequestBodyLimit 1048576` } })).toBe(200);
  });

  it('stores an mTLS rule path without Caddy placeholders, like every other path of a host', async () => {
    const created = await rulesRoute.POST(
      apiRequest('POST', '/x', tokens.teamA, { pathPattern: '/x{file./etc/hostname}/{env.SECRET}*', denyAll: true }),
      idParams(hosts.a)
    );
    expect(created.status, await created.clone().text()).toBe(201);
    expect((await json(created)).pathPattern).toBe('/x/*');
  });

  it('keeps Caddy placeholders out of the settings Caddy expands them in, for every non-administrator', () => {
    const writer = { userId: OPERATOR, role: 'user', isAdmin: false, customRole: null, permissions: new Set(['settings:write']), scopeTags: [] } as unknown as Access;
    const refused = (group: string, value: unknown) => expect(() => assertSettingsWriteAllowed(writer, group, value), group).toThrow(/Only administrators/);
    refused('general', { primaryDomain: 'example.com', acmeEmail: '{file./config/caddy/autosave.json}@example.com' });
    refused('acme', { caUrl: 'https://ca.example.com/dir/{env.HOSTNAME}' });
    refused('cloudflare', { apiToken: '{env.CF_TOKEN}' });
    refused('dns-provider', { providers: { powerdns: { server_url: 'https://dns.example.com', api_token: '{file./config/caddy/autosave.json}' } }, default: 'powerdns' });
    // Ordinary values, groups where placeholders are part of the feature, and administrators.
    expect(() => assertSettingsWriteAllowed(writer, 'general', { primaryDomain: 'example.com', acmeEmail: 'ops@example.com' })).not.toThrow();
    expect(() => assertSettingsWriteAllowed(writer, 'response-headers', { set: { 'X-Served-For': '{http.request.host}' }, remove: [] })).not.toThrow();
    expect(() => assertSettingsWriteAllowed(adminAccess(ADMIN), 'cloudflare', { apiToken: '{env.CF_TOKEN}' })).not.toThrow();
  });

  it('rejects malformed Caddy-bound scalars with a 400 (not a poisoned config apply)', async () => {
    const cases: Array<[string, object]> = [
      ['a bad load-balancer duration', { loadBalancer: { enabled: true, tryDuration: 'banana' } }],
      ['a bad health-check interval', { loadBalancer: { enabled: true, activeHealthCheck: { enabled: true, interval: 'soon' } } }],
      ['a malformed geoblock CIDR', { geoblock: { enabled: true, block_cidrs: ['not-a-cidr'] } }],
      ['a unix-socket DNS resolver', { dnsResolver: { enabled: true, resolvers: ['unix//x.sock'] } }],
      ['a placeholder DNS resolver', { dnsResolver: { enabled: true, resolvers: ['1.1.1.1:{env.P}'] } }],
      ['a malformed forward-auth trusted proxy', { forwardAuth: { enabled: true, provider: 'custom', authUpstream: 'http://authelia:9091', authEndpoint: '/api/verify', trustedProxies: ['garbage'] } }],
    ];
    for (const [label, extra] of cases) {
      const r = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({ tags: ['team-a'], ...extra })));
      expect(r.status, label).toBe(400);
    }
    // Valid values still work.
    const ok = await hostsRoute.POST(apiRequest('POST', '/x', tokens.teamA, newHost({
      tags: ['team-a'], domains: ['scalars-ok.example.com'],
      loadBalancer: { enabled: true, tryDuration: '5s' },
      dnsResolver: { enabled: true, resolvers: ['1.1.1.1', 'tcp/8.8.8.8:53'] },
      geoblock: { enabled: true, block_cidrs: ['10.0.0.0/8'] },
    })));
    expect(ok.status).toBe(201);
  });

  it('refuses referencing a certificate outside the role\'s certificate scope', async () => {
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { certificateId: certs.b }), idParams(hosts.a))).status).toBe(403);
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { certificateId: certs.shared }), idParams(hosts.a))).status).toBe(200);
    // Keeping the current certificate is always fine.
    expect((await hostRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { certificateId: certs.shared, name: 'Same' }), idParams(hosts.a))).status).toBe(200);
  });
});

describe('L4 proxy hosts', () => {
  it('lists, reads and changes only in-scope hosts', async () => {
    const list = await json(await l4sRoute.GET(apiRequest('GET', '/x', tokens.teamA)));
    expect(list.map((h: { name: string }) => h.name)).toEqual(['A db']);
    expect((await l4Route.GET(apiRequest('GET', '/x', tokens.teamA), idParams(l4.b))).status).toBe(404);
    expect((await l4Route.DELETE(apiRequest('DELETE', '/x', tokens.teamA), idParams(l4.b))).status).toBe(404);
    expect((await l4Route.PUT(apiRequest('PUT', '/x', tokens.teamA, { name: 'Mine' }), idParams(l4.a))).status).toBe(200);
  });

  it('needs a scope tag to create and refuses ports used outside the scope', async () => {
    const body = (extra: object) => ({ name: 'Redis', protocol: 'tcp', listenAddress: ':6379', upstreams: ['redis:6379'], ...extra });
    expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({})))).status).toBe(400);
    expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'], listenAddress: ':6432' })))).status).toBe(403);
    // Out-of-range / malformed upstream ports are a clean 400 (the model rejects them before Caddy would), never a 500.
    for (const upstream of ['caddy:67555', 'caddy:0', 'caddy:5432-5433']) {
      const r = await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'], upstreams: [upstream] })));
      expect([400, 403], upstream).toContain(r.status);
    }

    for (const listenAddress of ['unix//data/caddy/x:9000', 'fd/3:9000', '{env.X}:9000', 'tcp/:9000']) {
      expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'], listenAddress })))).status, listenAddress).toBe(403);
    }
    expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({
      tags: ['team-a'], listenAddress: ':6380', matcherType: 'tls_sni', matcherValue: ['{env.SECRET}'],
    })))).status).toBe(403);
    for (const upstream of ['caddy:2019', 'caddy:2019-2019', 'tcp/[::1]:2019', 'udp/caddy:2019', 'caddy:{env.PORT}', 'tcp/caddy:80', 'unix//run/caddy-admin/admin.sock']) {
      expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'], upstreams: [upstream] })))).status, upstream).toBe(403);
    }
    expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'], loadBalancer: { enabled: true, tryDuration: 'banana' } })))).status).toBe(400);
    expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'], loadBalancer: { enabled: true, activeHealthCheck: { enabled: true, port: 2019 } } })))).status).toBe(403);
    // The raw meta object would carry the same settings past these checks.
    expect((await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({
      tags: ['team-a'], meta: { load_balancer: { enabled: true, active_health_check: { enabled: true, port: 2019 } } },
    })))).status).toBe(403);
    expect((await l4Route.PUT(apiRequest('PUT', '/x', tokens.teamA, { meta: { geoblock: { enabled: true, block_cidrs: ['not-a-cidr'] } } }), idParams(l4.a))).status).toBe(403);
    // A host keeps the upstream and listen address an administrator gave it.
    const special = await l4sRoute.POST(apiRequest('POST', '/x', tokens.admin, body({ tags: ['team-a'], listenAddress: ':6390', upstreams: ['tcp/redis:6379'] })));
    expect(special.status, await special.clone().text()).toBe(201);
    const specialId = (await json(special)).id as number;
    expect((await l4Route.PUT(apiRequest('PUT', '/x', tokens.teamA, { name: 'Renamed', upstreams: ['tcp/redis:6379'] }), idParams(specialId))).status).toBe(200);
    expect((await l4Route.PUT(apiRequest('PUT', '/x', tokens.teamA, { upstreams: ['tcp/redis:6379', 'tcp/other:6379'] }), idParams(specialId))).status).toBe(403);
    expect((await l4Route.PUT(apiRequest('PUT', '/x', tokens.teamA, { upstreams: ['tcp/redis:6379'] }), idParams(l4.a))).status).toBe(403);
    const created = await l4sRoute.POST(apiRequest('POST', '/x', tokens.teamA, body({ tags: ['team-a'] })));
    expect(created.status).toBe(201);
    expect((await json(created)).tags).toEqual(['team-a']);
    expect((await l4Route.PUT(apiRequest('PUT', '/x', tokens.teamA, { listenAddress: ':6432' }), idParams(l4.a))).status).toBe(403);
  });
});

describe('certificates', () => {
  it('shows a scoped role the certificates its hosts use', async () => {
    const list = await json(await certsRoute.GET(apiRequest('GET', '/x', tokens.teamA)));
    expect(list.map((c: { name: string }) => c.name).sort()).toEqual(['A cert', 'Shared cert']);
    expect((await certRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(certs.b))).status).toBe(404);
    expect((await certRoute.GET(apiRequest('GET', '/x', tokens.teamA), idParams(certs.a))).status).toBe(200);
    expect(await json(await certsRoute.GET(apiRequest('GET', '/x', tokens.operator)))).toHaveLength(3);
  });

  it('changes or deletes a certificate only when every host using it is in scope', async () => {
    expect((await certRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { name: 'Ours' }), idParams(certs.shared))).status).toBe(403);
    expect((await certRoute.DELETE(apiRequest('DELETE', '/x', tokens.teamA), idParams(certs.shared))).status).toBe(403);
    expect((await certRoute.DELETE(apiRequest('DELETE', '/x', tokens.teamA), idParams(certs.b))).status).toBe(404);
    expect((await certRoute.PUT(apiRequest('PUT', '/x', tokens.teamA, { name: 'Ours' }), idParams(certs.a))).status).toBe(200);
  });

  it('cannot create certificates or reach CA certificates under a scope', async () => {
    const created = await certsRoute.POST(apiRequest('POST', '/x', tokens.teamA, { name: 'New', type: 'managed', domainNames: ['n.example.com'] }));
    expect(created.status).toBe(403);
    expect((await caRoute.GET(apiRequest('GET', '/x', tokens.teamA))).status).toBe(403);
    expect((await caRoute.GET(apiRequest('GET', '/x', tokens.operator))).status).toBe(200);
  });
});

describe('dashboard pages and actions', () => {
  const pageArgs = { searchParams: Promise.resolve({}) };

  it('lists only in-scope hosts on the pages', async () => {
    ctx.sessionUserId = TEAM_A;
    const page = await ProxyHostsPage(pageArgs) as { props: { hosts: Array<{ name: string }>; pagination: { total: number }; scopeTags: string[]; certificates: Array<{ name: string }> } };
    expect(page.props.hosts.map((h) => h.name).sort()).toEqual(['A', 'AB']);
    expect(page.props.pagination.total).toBe(2);
    expect(page.props.scopeTags).toEqual(['team-a']);
    expect(page.props.certificates.map((c) => c.name).sort()).toEqual(['A cert', 'Shared cert']);
    const l4Page = await L4ProxyHostsPage(pageArgs) as { props: { hosts: Array<{ name: string }> } };
    expect(l4Page.props.hosts.map((h) => h.name)).toEqual(['A db']);

    ctx.sessionUserId = ADMIN;
    const adminPage = await ProxyHostsPage(pageArgs) as { props: { hosts: unknown[] } };
    expect(adminPage.props.hosts).toHaveLength(4);
  });

  it('refuses actions on hosts outside the scope', async () => {
    ctx.sessionUserId = TEAM_A;
    const form = new FormData();
    form.set('name', 'Taken');
    expect(await updateProxyHostAction(hosts.b, undefined, form)).toMatchObject({ status: 'error', message: 'Proxy host not found' });
    expect(await deleteProxyHostAction(hosts.b)).toMatchObject({ status: 'error', message: 'Proxy host not found' });
    expect(await toggleProxyHostAction(hosts.b, false)).toMatchObject({ status: 'error' });
    expect(await deleteL4ProxyHostAction(l4.b)).toMatchObject({ status: 'error', message: 'L4 proxy host not found' });
    await expect(deleteCertificateAction(certs.shared)).rejects.toThrow(/outside your role's scope/);
    expect((await first(ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, hosts.b)).limit(1)))!.enabled).toBe(true);
  });

  it('creates a host from the form only with a scope tag', async () => {
    ctx.sessionUserId = TEAM_A;
    const form = new FormData();
    form.set('name', 'From form');
    form.set('domains', 'form.example.com');
    form.set('upstreams', 'backend:8080');
    expect(await createProxyHostAction(undefined, form)).toMatchObject({ status: 'error', message: expect.stringMatching(/team-a/) });
    form.set('tags', 'team-a');
    expect(await createProxyHostAction(undefined, form)).toMatchObject({ status: 'success' });
    const created = (await first(ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.name, 'From form')).limit(1)))!;
    expect(JSON.parse(created.tags)).toEqual(['team-a']);
  });
});

describe('role management from the dashboard', () => {
  const MANAGER = 7;
  const MEMBER = 8;

  beforeEach(async () => {
    await insertRole(ctx.db, 3, ['users:read', 'users:write', 'proxy_hosts:read'], [], 'Managers');
    await insertUser(ctx.db, MANAGER, 'viewer', 3);
    await insertUser(ctx.db, MEMBER, 'user');
  });

  it('assigns a custom role and takes it away', async () => {
    ctx.sessionUserId = ADMIN;
    expect(await updateUserRoleAction(MEMBER, 'custom:2')).toEqual({ ok: true });
    expect(await first(ctx.db.select().from(schema.users).where(eq(schema.users.id, MEMBER)).limit(1))).toMatchObject({ role: 'viewer', customRoleId: 2 });
    expect(await updateUserRoleAction(MEMBER, 'user')).toEqual({ ok: true });
    expect(await updateUserRoleAction(MEMBER, 'custom:abc')).toEqual({ ok: false, error: 'Invalid role' });
  });

  it('keeps a manager to the roles and users they cover', async () => {
    ctx.sessionUserId = MANAGER;
    expect(await updateUserRoleAction(MEMBER, 'admin')).toMatchObject({ ok: false });
    expect(await updateUserRoleAction(MEMBER, 'custom:1')).toMatchObject({ ok: false, error: expect.stringMatching(/only grant/) });
    expect(await updateUserStatusAction(ADMIN, 'disabled')).toMatchObject({ ok: false, error: expect.stringMatching(/cannot manage/) });
    expect(await deleteUserAction(ADMIN)).toMatchObject({ ok: false });
    expect(await updateUserRoleAction(MANAGER, 'user')).toEqual({ ok: false, error: 'Cannot change your own role' });
    const form = new FormData();
    form.set('email', 'new@example.com');
    form.set('password', 'Correct-Horse-9!');
    form.set('role', 'admin');
    expect(await createUserAction(form)).toMatchObject({ ok: false });
    form.set('role', 'viewer');
    expect(await createUserAction(form)).toEqual({ ok: true });
    expect(await first(ctx.db.select().from(schema.users).where(eq(schema.users.id, ADMIN)).limit(1))).toMatchObject({ role: 'admin', status: 'active' });
  });

  it('saves and deletes roles', async () => {
    ctx.sessionUserId = ADMIN;
    expect(await saveRoleAction(null, { name: 'Auditors', permissions: ['audit_log:read'] })).toEqual({ ok: true });
    const role = (await first(ctx.db.select().from(schema.customRoles).where(eq(schema.customRoles.name, 'Auditors')).limit(1)))!;
    expect(await saveRoleAction(role.id, { description: 'Read the log' })).toEqual({ ok: true });
    expect(await deleteRoleAction(role.id)).toEqual({ ok: true });
    expect(await first(ctx.db.select().from(schema.customRoles).where(eq(schema.customRoles.id, role.id)).limit(1))).toBeUndefined();
  });

  it('gives the Users page the roles and the picker', async () => {
    ctx.sessionUserId = MANAGER;
    const page = await UsersPage() as { props: { customRoles: Array<{ name: string }>; canWrite: boolean; canAssignAdmin: boolean; mfaPolicy: unknown } };
    expect(page.props.customRoles.map((role) => role.name).sort()).toEqual(['Managers', 'Operators', 'Team A']);
    expect(page.props).toMatchObject({ canWrite: true, canAssignAdmin: false, mfaPolicy: null });
  });
});
