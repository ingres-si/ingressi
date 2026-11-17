/**
 * Access lists for some paths of a host (#387):
 *  - each entry is a path route in a subroute right after the host's own
 *    list, running the list's rules and then its Basic Auth;
 *  - a list that does not exist denies the path (never leaves it open);
 *  - writes are validated strictly, deleting a list removes its entries, and
 *    a non-administrator needs access_lists:write to change a host's lists.
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
import { createProxyHost, getProxyHost, updateProxyHost } from '../../src/lib/models/proxy-hosts';
import { createAccessList, deleteAccessList, ensureBlockedSourcesList } from '../../src/lib/models/access-lists';
import { assertProxyHostWriteAllowed } from '../../src/lib/access-scope';
import { buildCaddyDocument } from '../../src/lib/caddy';
import type { Access, Permission } from '../../src/lib/permissions';
import * as schema from '../../src/lib/db/schema';
import { eq } from 'drizzle-orm';

type Handler = Record<string, any>;
type Doc = Awaited<ReturnType<typeof buildCaddyDocument>>;

function routesOf(doc: Doc): Array<Record<string, any>> {
  return (doc.apps as any).http.servers.ingressi.routes;
}

/** The handle array of the host's catch-all route. */
function hostHandle(doc: Doc, domain: string): Handler[] {
  const route = routesOf(doc).find((item) => item.match?.[0]?.host?.includes(domain) && !item.match[0].expression && !item.match[0].path);
  expect(route, `route of ${domain}`).toBeDefined();
  return route!.handle;
}

function pathSubroute(handle: Handler[]): Handler | undefined {
  return handle.find((h) => h.handler === 'subroute' && h.routes?.some((r: any) => r.match?.[0]?.path && r.handle?.some((x: any) => x.handler === 'invoke' || x.handler === 'authentication' || x.key === 'access_list')));
}

async function officeList() {
  return createAccessList(
    {
      name: 'Office',
      defaultAction: 'deny',
      rules: [{ action: 'allow', kind: 'ip', values: ['203.0.113.0/26'] }],
      users: [{ username: 'alice', password: 'Alice-Passw0rd!' }],
    },
    1
  );
}

function host(name: string, extra: Record<string, unknown> = {}) {
  return createProxyHost({ name, domains: [`${name}.example.com`], upstreams: ['10.0.0.5:8080'], ...extra } as never, 1);
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

describe('path access lists in the Caddy document', () => {
  it('runs the list rules and Basic Auth for the path only, after the host list and before the upstream', async () => {
    const list = await officeList();
    const hostList = await createAccessList({ name: 'Blocklist', rules: [{ action: 'deny', kind: 'ip', values: ['198.51.100.0/24'] }] }, 1);
    await host('blog', { accessListId: hostList.id, pathAccessLists: [{ path: '/wp-admin/*', accessListId: list.id }, { path: '/wp-login.php', accessListId: list.id }] });

    const doc = await buildCaddyDocument();
    const handle = hostHandle(doc, 'blog.example.com');
    const hostInvoke = handle.findIndex((h) => h.handler === 'invoke' && h.name === `ingressi_acl_${hostList.id}`);
    const sub = pathSubroute(handle)!;
    expect(sub).toBeDefined();
    expect(handle.indexOf(sub)).toBe(hostInvoke + 1);
    expect(handle.findIndex((h) => h.handler === 'reverse_proxy')).toBeGreaterThan(handle.indexOf(sub));
    // The host itself has no Basic Auth: only the paths ask for it.
    expect(handle.some((h) => h.handler === 'authentication')).toBe(false);

    expect(sub.routes.map((r: any) => r.match)).toEqual([[{ path: ['/wp-admin/*'] }], [{ path: ['/wp-login.php'] }]]);
    for (const route of sub.routes) {
      expect(route.terminal).toBeUndefined();
      expect(route.handle[0]).toEqual({ handler: 'invoke', name: `ingressi_acl_${list.id}` });
      expect(route.handle[1].handler).toBe('authentication');
      expect(route.handle[1].providers.http_basic.accounts[0].username).toBe('alice');
    }
  });

  it('applies on the routes of location rules too', async () => {
    const list = await officeList();
    await host('api', { pathAccessLists: [{ path: '/auth/*', accessListId: list.id }], locationRules: [{ path: '/auth/*', upstreams: ['10.0.0.6:9000'] }] });
    const doc = await buildCaddyDocument();
    const location = routesOf(doc).find((r) => r.match?.[0]?.host?.includes('api.example.com') && r.match[0].path?.includes('/auth/*'));
    expect(location).toBeDefined();
    expect(pathSubroute(location!.handle)).toBeDefined();
  });

  it('denies a path whose list no longer exists', async () => {
    const list = await officeList();
    const created = await host('app', { pathAccessLists: [{ path: '/admin/*', accessListId: list.id }] });
    // A stale reference, as an import or a replica could leave behind.
    const row = (await ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.id, created.id)))[0];
    const meta = JSON.parse(row.meta!);
    meta.path_access_lists[0].access_list_id = 9999;
    await ctx.db.update(schema.proxyHosts).set({ meta: JSON.stringify(meta) }).where(eq(schema.proxyHosts.id, created.id));

    const sub = pathSubroute(hostHandle(await buildCaddyDocument(), 'app.example.com'))!;
    expect(sub.routes).toEqual([
      {
        match: [{ path: ['/admin/*'] }],
        handle: [
          { handler: 'log_append', key: 'access_list', value: '9999' },
          { handler: 'static_response', status_code: 403, body: 'Forbidden' },
        ],
      },
    ]);
  });
});

describe('path access list writes', () => {
  it('round-trips, and null removes them', async () => {
    const list = await officeList();
    const created = await host('app', { pathAccessLists: [{ path: ' /admin/* ', accessListId: list.id }, { path: '/admin/*', accessListId: list.id }] });
    expect(created.pathAccessLists).toEqual([{ path: '/admin/*', accessListId: list.id }]);
    const cleared = await updateProxyHost(created.id, { pathAccessLists: null }, 1);
    expect(cleared.pathAccessLists).toEqual([]);
  });

  it.each([
    [[{ path: 'admin', accessListId: 1 }], 'must start with /'],
    [[{ path: '/a/{http.request.host}', accessListId: 1 }], 'cannot contain { or }'],
    [[{ path: '/admin', accessListId: 0 }], 'accessListId must be'],
    [[{ path: '', accessListId: 1 }], 'path is required'],
    ['/admin', 'must be a list'],
  ])('refuses %j', async (value, message) => {
    await expect(host('bad', { pathAccessLists: value })).rejects.toThrow(message);
  });

  it('refuses a list that does not exist and the Blocked sources list', async () => {
    await expect(host('a', { pathAccessLists: [{ path: '/x', accessListId: 4242 }] })).rejects.toThrow('does not exist');
    const blocked = await ensureBlockedSourcesList();
    await expect(host('b', { pathAccessLists: [{ path: '/x', accessListId: blocked.id }] })).rejects.toThrow('Blocked sources');
  });

  it('removes the entries of a deleted list and keeps the others', async () => {
    const list = await officeList();
    const other = await createAccessList({ name: 'Other', rules: [{ action: 'deny', kind: 'ip', values: ['192.0.2.1'] }] }, 1);
    const created = await host('app', {
      pathBlocks: [{ path: '/metrics', status: 404 }],
      pathAccessLists: [{ path: '/admin/*', accessListId: list.id }, { path: '/ops/*', accessListId: other.id }],
    });
    await deleteAccessList(list.id, 1);
    const after = (await getProxyHost(created.id))!;
    expect(after.pathAccessLists).toEqual([{ path: '/ops/*', accessListId: other.id }]);
    expect(after.pathBlocks).toEqual([{ path: '/metrics', status: 404 }]);
  });
});

describe('path access lists and non-administrators', () => {
  const access = (permissions: Permission[]): Access =>
    ({ userId: 2, role: 'viewer', isAdmin: false, customRole: { id: 1, name: 'Editors' }, permissions: new Set(permissions), scopeTags: [] }) as unknown as Access;

  it("needs access_lists:write to add or remove a host's lists, not to keep them", async () => {
    const list = await officeList();
    const existing = await host('app', { accessListId: list.id, pathAccessLists: [{ path: '/admin/*', accessListId: list.id }] });
    const reader = access(['proxy_hosts:read', 'proxy_hosts:write', 'access_lists:read'] as Permission[]);
    const writer = access(['proxy_hosts:write', 'access_lists:write'] as Permission[]);
    const changes = [
      { pathAccessLists: [...existing.pathAccessLists, { path: '/other/*', accessListId: list.id }] },
      { pathAccessLists: [] },
      { pathAccessLists: null },
      { accessListId: null },
    ];
    for (const input of changes) {
      await expect(assertProxyHostWriteAllowed(reader, input as never, existing)).rejects.toThrow('access_lists:write');
      await expect(assertProxyHostWriteAllowed(writer, input as never, existing)).resolves.toBeUndefined();
    }
    // Saving the host with its lists unchanged needs nothing more.
    await expect(
      assertProxyHostWriteAllowed(reader, { accessListId: list.id, pathAccessLists: [{ path: ' /admin/* ', accessListId: list.id }] }, existing)
    ).resolves.toBeUndefined();
    // A new host with a list needs it too.
    await expect(assertProxyHostWriteAllowed(reader, { accessListId: list.id }, null)).rejects.toThrow('access_lists:write');
    await expect(assertProxyHostWriteAllowed(reader, { accessListId: null, pathAccessLists: [] }, null)).resolves.toBeUndefined();
  });
});
