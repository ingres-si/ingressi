/**
 * The host editor's server side: its save and review actions
 * (app/(dashboard)/proxy-hosts/editor-actions.ts), the REST previews
 * (POST /api/v1/proxy-hosts/preview and /api/v1/proxy-hosts/{id}/preview)
 * and the edit and new pages' data. Saves go through the same scope checks
 * and change approval gate as the REST API; previews store nothing.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { createTestDb, type TestDb } from '../helpers/db';
import * as schema from '../../src/lib/db/schema';
import { apiRequest, idParams, json } from '../helpers/custom-roles';
import { ADMIN, ALICE, BOB, DAVE, hostRow, insertPolicy, requestRow, seedApprovals, type Hosts, type Tokens } from '../helpers/approvals';

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
vi.mock('next/navigation', () => ({
  redirect: (url: string) => { throw new Error(`REDIRECT:${url}`); },
  notFound: () => { throw new Error('NOT_FOUND'); },
}));
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));
vi.mock('@/src/lib/upstream-health', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/src/lib/upstream-health')>()),
  getProxyHostHealth: async () => ({ status: 'unchecked', caddyReachable: true, upstreams: [], healthChecks: { active: null, passive: null } }),
}));

import { previewProxyHostEditorAction, saveProxyHostEditorAction } from '../../app/(dashboard)/proxy-hosts/editor-actions';
import { toEditorCertificate } from '../../app/(dashboard)/proxy-hosts/editor-data';
import EditProxyHostPage from '../../app/(dashboard)/proxy-hosts/[id]/edit/page';
import ProxyHostPage from '../../app/(dashboard)/proxy-hosts/[id]/page';
import NewProxyHostPage from '../../app/(dashboard)/proxy-hosts/new/page';
import * as createPreviewRoute from '../../app/api/v1/proxy-hosts/preview/route';
import * as updatePreviewRoute from '../../app/api/v1/proxy-hosts/[id]/preview/route';
import * as approveRoute from '../../app/api/v1/change-requests/[id]/approve/route';
import { first } from '@/src/lib/db/ops';
import { setManagedCertificateProbeForTests } from '@/src/lib/managed-certificates';
import { saveGeoBlockSettings, saveTrustedProxiesSettings } from '@/src/lib/settings';
import { createSelfSignedServerCertificate } from '../helpers/certs';

let tokens: Tokens;
let hosts: Hosts;

beforeEach(async () => {
  ctx.db = createTestDb();
  vi.clearAllMocks();
  ({ tokens, hosts } = await seedApprovals(ctx.db));
  await insertPolicy(ctx.db, { name: 'Production' });
});


async function changeRequests() {
  return await ctx.db.select().from(schema.changeRequests);
}

describe('host editor save', () => {
  it('creates an unprotected host from the editor payload, with its forward-auth grants', async () => {
    ctx.sessionUserId = ADMIN;
    const result = await saveProxyHostEditorAction(null, {
      host: {
        name: 'Editor host',
        domains: ['editor.example.com'],
        upstreams: ['http://10.0.0.5:8080'],
        tags: ['dev'],
        sslForced: false,
        hstsSubdomains: true,
        ingressiForwardAuth: { enabled: true, protected_paths: null, excluded_paths: ['/health'] },
      },
      forwardAuthAccess: { userIds: [BOB], groupIds: [] },
    });
    expect(result).toMatchObject({ status: 'saved', message: 'Created Editor host.' });
    const row = (await first(ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.name, 'Editor host')).limit(1)))!;
    expect(row).toMatchObject({ sslForced: false, hstsSubdomains: true });
    expect(result.status === 'saved' && result.hostId).toBe(row.id);
    expect(await ctx.db.select().from(schema.forwardAuthAccess)).toMatchObject([{ proxyHostId: row.id, userId: BOB }]);
  });

  it('says a host stored while Caddy is down is saved but not live yet, for a new host and for a change', async () => {
    ctx.sessionUserId = ADMIN;
    const { applyCaddyConfig } = await import('@/src/lib/caddy');
    const { CaddyApplyError } = await import('@/src/lib/caddy-apply-error');
    vi.mocked(applyCaddyConfig).mockRejectedValueOnce(new CaddyApplyError('Unable to reach Caddy API', 'CADDY_UNREACHABLE'));
    const created = await saveProxyHostEditorAction(null, { host: { name: 'Offline', domains: ['offline.example.com'], upstreams: ['http://10.0.0.9:80'] } });
    const row = (await first(ctx.db.select().from(schema.proxyHosts).where(eq(schema.proxyHosts.name, 'Offline')).limit(1)))!;
    expect(created).toEqual({ status: 'saved', hostId: row.id, message: expect.stringMatching(/^Saved, but not live yet: Unable to reach Caddy API\./) });

    vi.mocked(applyCaddyConfig).mockRejectedValueOnce(new CaddyApplyError('Unable to reach Caddy API', 'CADDY_UNREACHABLE'));
    const updated = await saveProxyHostEditorAction(row.id, { host: { name: 'Offline 2' } });
    expect(updated).toMatchObject({ status: 'saved', hostId: row.id, message: expect.stringContaining('not live yet') });
  });

  it('refuses a new host without a name or domains list', async () => {
    ctx.sessionUserId = ADMIN;
    expect(await saveProxyHostEditorAction(null, { host: { domains: ['x.example.com'], upstreams: ['a:1'] } })).toEqual({ status: 'error', message: 'Name is required' });
    expect(await saveProxyHostEditorAction(null, { host: { name: 'X', domains: 'x.example.com', upstreams: ['a:1'] } })).toEqual({
      status: 'error',
      message: 'domains must be a list of strings',
    });
    expect(await saveProxyHostEditorAction(null, 'not an object')).toMatchObject({ status: 'error', message: "The change must contain the host's fields" });
  });

  it('submits a change of a protected host for approval, with the reason', async () => {
    ctx.sessionUserId = ALICE;
    const result = await saveProxyHostEditorAction(hosts.prod, { host: { name: 'Renamed' }, note: 'Ticket CHG-7' });
    expect(result).toMatchObject({ status: 'submitted', requestStatus: 'pending', hostId: hosts.prod, message: expect.stringMatching(/^Submitted for approval as change request #\d+/) });
    expect((await hostRow(ctx.db, hosts.prod))!.name).toBe('App');
    const requestId = result.status === 'submitted' ? result.requestId : 0;
    expect(await requestRow(ctx.db, requestId)).toMatchObject({ note: 'Ticket CHG-7', requestedBy: ALICE });
    const approved = await json(await approveRoute.POST(apiRequest('POST', '/x', tokens.bob), idParams(requestId)));
    expect(approved.status).toBe('applied');
    expect((await hostRow(ctx.db, hosts.prod))!.name).toBe('Renamed');
  });

  it('applies an emergency change only for users allowed to', async () => {
    ctx.sessionUserId = ALICE;
    expect(await saveProxyHostEditorAction(hosts.prod, { host: { name: 'Now' }, emergencyReason: 'Outage INC-1234 needs it' })).toEqual({
      status: 'error',
      message: 'Emergency changes need the approvals:emergency permission',
    });
    ctx.sessionUserId = ADMIN;
    const applied = await saveProxyHostEditorAction(hosts.prod, { host: { name: 'Now' }, emergencyReason: 'Outage INC-1234 needs it' });
    expect(applied).toMatchObject({ status: 'submitted', requestStatus: 'applied' });
    expect((await hostRow(ctx.db, hosts.prod))!.name).toBe('Now');
  });

  it('runs the scope checks: custom Caddy JSON is for administrators', async () => {
    ctx.sessionUserId = ALICE;
    expect(await saveProxyHostEditorAction(hosts.dev, { host: { customReverseProxyJson: '{"headers":{}}' } })).toEqual({
      status: 'error',
      message: 'Only administrators can set custom Caddy JSON on a proxy host',
    });
    expect(await saveProxyHostEditorAction(hosts.dev, { host: { name: 'Dev 2' } })).toMatchObject({ status: 'saved', hostId: hosts.dev });
    expect((await hostRow(ctx.db, hosts.dev))!.name).toBe('Dev 2');
  });

  it('needs proxy_hosts:write', async () => {
    ctx.sessionUserId = DAVE;
    expect(await saveProxyHostEditorAction(hosts.dev, { host: { name: 'Nope' } })).toMatchObject({ status: 'error' });
    expect(await previewProxyHostEditorAction(hosts.dev, { host: { name: 'Nope' } })).toMatchObject({ status: 'error' });
    expect((await hostRow(ctx.db, hosts.dev))!.name).toBe('Dev');
  });
});

describe('host editor save: addresses that skip sign-in', () => {
  const providers = [
    { name: 'Authentik', body: (sources: unknown) => ({ authentik: { enabled: true, outpostDomain: 'outpost.example.com', outpostUpstream: 'http://outpost:9000', bypassSources: sources } }), key: 'authentik', field: 'bypass_sources' },
    { name: 'generic forward auth', body: (sources: unknown) => ({ forwardAuth: { enabled: true, provider: 'authelia', authUpstream: 'http://authelia:9091', bypassSources: sources } }), key: 'forward_auth', field: 'bypass_sources' },
    { name: 'built-in sign-in', body: (sources: unknown) => ({ ingressiForwardAuth: { enabled: true, bypass_sources: sources } }), key: 'cpm_forward_auth', field: 'bypass_sources' },
  ];

  it.each(providers)('stores the list the editor sends for $name, normalized, and refuses a bad one', async ({ body, key, field }) => {
    ctx.sessionUserId = ADMIN;
    const created = await saveProxyHostEditorAction(null, {
      host: { name: 'Skipper', domains: ['skip.example.com'], upstreams: ['http://10.0.0.5:8080'], sslForced: false, ...body(['192.168.1.77/24', 'private_ranges']) },
    });
    expect(created).toMatchObject({ status: 'saved' });
    const hostId = created.status === 'saved' ? created.hostId : 0;
    const stored = JSON.parse((await hostRow(ctx.db, hostId))!.meta as string);
    expect(stored[key][field]).toEqual(['192.168.1.0/24', 'private_ranges']);

    const refused = await saveProxyHostEditorAction(hostId, { host: body(['192.168.1.0/24', 'nope']) });
    expect(refused).toMatchObject({ status: 'error', message: expect.stringContaining('"nope" is not an IP address, a CIDR range or private_ranges') });
    expect(JSON.parse((await hostRow(ctx.db, hostId))!.meta as string)[key][field]).toEqual(['192.168.1.0/24', 'private_ranges']);

    const cleared = await saveProxyHostEditorAction(hostId, { host: body([]) });
    expect(cleared).toMatchObject({ status: 'saved' });
    expect(JSON.parse((await hostRow(ctx.db, hostId))!.meta as string)[key][field]).toBeUndefined();
  });
});

describe('host editor review', () => {
  it('says which policy applies, what changes and the impact, and stores nothing', async () => {
    ctx.sessionUserId = ALICE;
    const result = await previewProxyHostEditorAction(hosts.prod, { host: { name: 'Renamed', domains: ['app.example.com', 'new.example.com'] } });
    expect(result.status).toBe('ok');
    if (result.status !== 'ok') return;
    expect(result.preview.approval).toMatchObject({
      required: true,
      policies: [{ name: 'Production' }],
      requiredApprovals: 1,
      operations: ['update'],
      emergencyAllowed: false,
      window: { restricted: false },
    });
    expect(result.preview.changes).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: 'host.name', before: 'App', after: 'Renamed' })])
    );
    expect(result.preview.impact.caddy.certificateRequests).toEqual(['new.example.com']);
    expect(result.preview.impact.lines.map((line) => line.key)).toEqual(['hosts', 'caddy', 'when']);
    expect(await changeRequests()).toHaveLength(0);
    expect((await hostRow(ctx.db, hosts.prod))!.name).toBe('App');
  });

  it('says no approval is needed for an unprotected host', async () => {
    ctx.sessionUserId = ALICE;
    const result = await previewProxyHostEditorAction(hosts.dev, { host: { enabled: false } });
    expect(result).toMatchObject({ status: 'ok', preview: { approval: { required: false, requiredApprovals: 0, operations: ['disable'] } } });
  });

  it('answers through the REST API for creates and updates', async () => {
    const created = await createPreviewRoute.POST(
      apiRequest('POST', '/api/v1/proxy-hosts/preview', tokens.alice, { name: 'Shop', domains: ['shop.example.com'], upstreams: ['http://shop:80'], tags: ['prod'] })
    );
    expect(created.status).toBe(200);
    expect(await json(created)).toMatchObject({ approval: { required: true, operations: ['create'] }, impact: { hosts: [{ name: 'Shop', change: 'create' }] } });

    const updated = await updatePreviewRoute.POST(apiRequest('POST', `/api/v1/proxy-hosts/${hosts.dev}/preview`, tokens.alice, { name: 'Dev 2' }), idParams(hosts.dev));
    expect(updated.status).toBe(200);
    expect(await json(updated)).toMatchObject({ approval: { required: false }, changes: [{ path: 'host.name', before: 'Dev', after: 'Dev 2' }] });

    const missing = await updatePreviewRoute.POST(apiRequest('POST', '/api/v1/proxy-hosts/9999/preview', tokens.alice, { name: 'X' }), idParams(9999));
    expect(missing.status).toBe(404);
    const reader = await updatePreviewRoute.POST(apiRequest('POST', `/api/v1/proxy-hosts/${hosts.dev}/preview`, tokens.dave, { name: 'X' }), idParams(hosts.dev));
    expect(reader.status).toBe(403);
    expect(await changeRequests()).toHaveLength(0);
  });
});

describe('host editor pages', () => {
  it('put the editor on the host\'s page for writers, with the approval context; a missing host is not found', async () => {
    ctx.sessionUserId = ALICE;
    const page = (await ProxyHostPage({ params: Promise.resolve({ id: String(hosts.prod) }) })) as { props: { editor: Record<string, any> } };
    expect(page.props.editor).toMatchObject({ mode: 'edit', host: { id: hosts.prod, name: 'App' }, isAdmin: false, canChooseUsers: true });
    expect(page.props.editor.approval.policies).toMatchObject([{ name: 'Production' }]);
    await expect(ProxyHostPage({ params: Promise.resolve({ id: '9999' }) })).rejects.toThrow('NOT_FOUND');
    await expect(ProxyHostPage({ params: Promise.resolve({ id: 'abc' }) })).rejects.toThrow('NOT_FOUND');
  });

  it('leave the editor out for roles that may only read hosts', async () => {
    ctx.sessionUserId = DAVE;
    const page = (await ProxyHostPage({ params: Promise.resolve({ id: String(hosts.dev) }) }).catch((error: Error) => error)) as { props?: { editor: unknown } } | Error;
    if (page instanceof Error) expect(page.message).toMatch(/NOT_FOUND|REDIRECT/);
    else expect(page.props?.editor).toBeNull();
  });

  it('send the old editor address to the host\'s page, at the section asked for', async () => {
    await expect(EditProxyHostPage({ params: Promise.resolve({ id: '7' }), searchParams: Promise.resolve({ section: 'security' }) })).rejects.toThrow('REDIRECT:/proxy-hosts/7#security');
    await expect(EditProxyHostPage({ params: Promise.resolve({ id: '7' }), searchParams: Promise.resolve({}) })).rejects.toThrow('REDIRECT:/proxy-hosts/7');
    await expect(EditProxyHostPage({ params: Promise.resolve({ id: '7' }), searchParams: Promise.resolve({ section: 'nope' }) })).rejects.toThrow(/^REDIRECT:\/proxy-hosts\/7$/);
  });

  it('start a new host from ?domain= and a copy from ?from=', async () => {
    ctx.sessionUserId = ADMIN;
    const fresh = (await NewProxyHostPage({ searchParams: Promise.resolve({ domain: 'New.Example.com' }) })) as { props: { data: Record<string, any> } };
    expect(fresh.props.data).toMatchObject({ mode: 'create', host: null, template: null, initialDomain: 'new.example.com', isAdmin: true });
    const copy = (await NewProxyHostPage({ searchParams: Promise.resolve({ from: String(hosts.dev), domain: '<script>' }) })) as { props: { data: Record<string, any> } };
    expect(copy.props.data).toMatchObject({ template: { id: hosts.dev }, initialDomain: null });
  });

  it('read what Caddy serves for the names of the managed certificate a host uses, not the host\'s own', async () => {
    ctx.sessionUserId = ADMIN;
    const shop = createSelfSignedServerCertificate('shop.example.com', ['shop.example.com'], 60);
    setManagedCertificateProbeForTests(async (servername) => (servername === 'shop.example.com' ? { kind: 'certificate', pem: shop.certificatePem } : { kind: 'missing' }));
    try {
      const now = new Date().toISOString();
      const addCertificate = async (type: 'managed' | 'imported') =>
        (await first(ctx.db.insert(schema.certificates).values({ name: `Shop ${type}`, type, domainNames: '["shop.example.com"]', createdAt: now, updatedAt: now }).returning()))!.id;
      const served = async () => {
        const page = (await ProxyHostPage({ params: Promise.resolve({ id: String(hosts.prod) }) })) as { props: { editor: Record<string, any> } };
        return page.props.editor.servedCertificate;
      };
      const use = (certificateId: number | null) => ctx.db.update(schema.proxyHosts).set({ certificateId }).where(eq(schema.proxyHosts.id, hosts.prod));

      // Automatic: app.example.com, which Caddy has no certificate for.
      expect(await served()).toBeNull();

      await use(await addCertificate('managed'));
      expect(await served()).toMatchObject({ domains: ['shop.example.com'], issuer: 'Ingressi E2E', keyType: 'RSA 2048' });

      // An imported certificate is read from its PEM, not from Caddy.
      await use(await addCertificate('imported'));
      expect(await served()).toBeNull();
    } finally {
      setManagedCertificateProbeForTests(null);
    }
  });

  it('tell the editor whether the global geo blocking rules are on, and whether they block anything', async () => {
    ctx.sessionUserId = ADMIN;
    const globalGeo = async () => {
      const page = (await ProxyHostPage({ params: Promise.resolve({ id: String(hosts.prod) }) })) as { props: { editor: Record<string, any> } };
      return page.props.editor.geoblockGlobal;
    };
    const rules = {
      enabled: true, block_countries: [], block_continents: [], block_asns: [], block_cidrs: [], block_ips: [],
      allow_countries: [], allow_continents: [], allow_asns: [], allow_cidrs: [], allow_ips: [],
      trusted_proxies: [], fail_closed: false, response_status: 403, response_body: 'Forbidden', response_headers: {}, redirect_url: '',
    };
    expect(await globalGeo()).toBeNull();

    // Allow rules only make exceptions to block rules.
    await saveGeoBlockSettings({ ...rules, allow_countries: ['AT'] });
    expect(await globalGeo()).toEqual({ enabled: true, blocks: false });

    await saveGeoBlockSettings({ ...rules, enabled: false, block_cidrs: ['0.0.0.0/0'] });
    expect(await globalGeo()).toEqual({ enabled: false, blocks: true });
  });

  it('tell the editor how Caddy works out the client address, for the sign-in bypass', async () => {
    ctx.sessionUserId = ADMIN;
    const clientAddress = async () => {
      const page = (await ProxyHostPage({ params: Promise.resolve({ id: String(hosts.prod) }) })) as { props: { editor: Record<string, any> } };
      return page.props.editor.clientAddress;
    };
    // Nothing trusted: the address of the connection.
    expect(await clientAddress()).toEqual({ proxiesTrusted: false, forwardedForForgeable: false });
    // Trusted proxies and the default header, read left to right: forgeable through a proxy that appends.
    await saveTrustedProxiesSettings({ ranges: ['172.18.0.0/16'] });
    expect(await clientAddress()).toEqual({ proxiesTrusted: true, forwardedForForgeable: true });
    await saveTrustedProxiesSettings({ ranges: ['172.18.0.0/16'], client_ip_headers: ['X-Forwarded-For'] });
    expect((await clientAddress()).forwardedForForgeable).toBe(true);
    // Strict parsing, or a header the proxy sets itself, is not.
    await saveTrustedProxiesSettings({ ranges: ['172.18.0.0/16'], strict: true });
    expect(await clientAddress()).toEqual({ proxiesTrusted: true, forwardedForForgeable: false });
    await saveTrustedProxiesSettings({ ranges: ['172.18.0.0/16'], client_ip_headers: ['Cf-Connecting-Ip'] });
    expect(await clientAddress()).toEqual({ proxiesTrusted: true, forwardedForForgeable: false });
    await saveTrustedProxiesSettings({ ranges: [' ', ''] });
    expect(await clientAddress()).toEqual({ proxiesTrusted: false, forwardedForForgeable: false });
  });

  it('keep certificate keys and PEM out of the editor', () => {
    const view = toEditorCertificate({
      id: 3,
      name: 'Imported',
      type: 'imported',
      domainNames: ['example.com'],
      autoRenew: false,
      providerOptions: { provider: 'cloudflare', api_token: 'provider-secret-sentinel' },
      certificatePem: 'not a pem',
      privateKeyPem: 'private-key-sentinel',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(view).toEqual({ id: 3, name: 'Imported', type: 'imported', domains: ['example.com'], expiresAt: null, issuer: null, provider: null });
  });

  it('give a managed certificate\'s provider by name only', () => {
    const view = toEditorCertificate({
      id: 4,
      name: 'Shop',
      type: 'managed',
      domainNames: ['shop.example.com'],
      autoRenew: true,
      providerOptions: { provider: 'godaddy', api_token: 'provider-secret-sentinel' },
      certificatePem: null,
      privateKeyPem: null,
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(view).toEqual({ id: 4, name: 'Shop', type: 'managed', domains: ['shop.example.com'], expiresAt: null, issuer: null, provider: 'godaddy' });
    expect(JSON.stringify(view)).not.toContain('provider-secret-sentinel');
  });
});
