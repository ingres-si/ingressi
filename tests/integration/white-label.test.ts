/**
 * White-label (ee/white-label): the REST API and dashboard actions, uploads,
 * the public image route, the cache, instance sync, and where the branding
 * shows up (page metadata, sign-in pages, e-mails) and where it must not
 * (identifiers).
 */
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { eq } from 'drizzle-orm';
import { NextRequest } from 'next/server';
import { createTestDb, disableForeignKeys, type TestDb } from '../helpers/db';
import { makeIco, makeJpeg, makePng, textChunk } from '../helpers/images';
import * as schema from '../../src/lib/db/schema';

const ctx = vi.hoisted(() => ({ db: null as unknown as TestDb }));
const mail = vi.hoisted(() => ({ sendMail: vi.fn(), close: vi.fn() }));

vi.mock('../../src/lib/db', async () => (await import('../helpers/db-module')).mockDbModule(() => ctx.db));
vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));
vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: vi.fn(), push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}));
vi.mock('@/src/lib/auth', () => ({
  auth: vi.fn(async () => null),
  checkSameOrigin: vi.fn(() => null),
  requirePermission: vi.fn(() => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireAdmin())),
  requireAdmin: vi.fn(async () => ({ user: { id: '1', role: 'admin' } })),
}));
vi.mock('@/src/lib/auth-client', () => ({ authClient: { signIn: { social: vi.fn() } } }));
vi.mock('@/src/lib/api-auth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/src/lib/api-auth')>()),
  requireApiPermission: vi.fn((request: unknown) => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireApiAdmin(request))),
  requireApiAdmin: vi.fn(async () => ({ userId: 1, role: 'admin', authMethod: 'bearer' })),
}));
vi.mock('@/src/lib/l4-ports', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/src/lib/l4-ports')>()),
  applyL4Ports: vi.fn(async () => ({ state: 'idle' })),
  getL4PortsDiff: vi.fn(async () => ({ needsApply: false })),
}));
vi.mock('nodemailer', () => ({ createTransport: () => ({ sendMail: mail.sendMail, close: mail.close }) }));

import { GET, PUT, DELETE } from '@/app/api/v1/branding/route';
import { PUT as PUT_ASSET, DELETE as DELETE_ASSET } from '@/app/api/v1/branding/assets/[asset]/route';
import { GET as GET_IMAGE } from '@/app/api/branding/[asset]/route';
import { GET as getOpenApi } from '@/app/api/v1/openapi.json/route';
import { deleteBrandingAssetAction, resetBrandingAction, saveBrandingAction, uploadBrandingAssetAction } from '@/ee/white-label/ui/actions';
import { generateMetadata } from '@/app/layout';
import LoginClient from '@/app/(auth)/login/LoginClient';
import PortalLoginForm from '@/app/(auth)/portal/PortalLoginForm';
import middleware from '@/proxy';
import { revalidatePath } from 'next/cache';
import { ApiAuthError, requireApiAdmin } from '@/src/lib/api-auth';
import { logAuditEvent } from '@/src/lib/audit';
import { isAdminLevel, PERMISSION_AREAS } from '@/src/lib/permissions';
import { applySyncPayload, buildSyncPayload, buildSyncPayloadFromContent, type SyncPayload } from '@/src/lib/instance-sync';
import { emptyConfigContent } from '@/src/lib/config-content';
import { authenticatorIssuer } from '@/src/lib/mfa-auth';
import { brandingThemeCss, DEFAULT_BRANDING, getBranding, loadBranding, refreshBranding, resetBrandingCache, toPublicBranding } from '@/ee/white-label/store';
import { cachedValuesSettled } from '@/src/lib/db/cached-value';
import { BrandingProvider } from '@/ee/white-label/ui/BrandingProvider';
import { deriveDarkAccent, foregroundFor } from '@/ee/white-label/colors';
import { WHITE_LABEL_SETTING_KEY, type BrandingView } from '@/ee/white-label/types';
import { buildEmail, buildWebhookBody, pagerDutyDedupKey, testNotification } from '@/ee/alerting/format';
import { sendEmailMessage } from '@/ee/alerting/deliver';
import { first as dbFirst } from '@/src/lib/db/ops';

async function setRow(key: string, value: unknown, updatedAt = new Date().toISOString()) {
  const json = JSON.stringify(value);
  await ctx.db.insert(schema.settings).values({ key, value: json, updatedAt })
    .onConflictDoUpdate({ target: schema.settings.key, set: { value: json, updatedAt } });
}

async function row(key: string) {
  return await dbFirst(ctx.db.select().from(schema.settings).where(eq(schema.settings.key, key)).limit(1));
}

function jsonRequest(method: string, body?: unknown): any {
  return {
    method,
    headers: new Headers(),
    nextUrl: new URL('http://localhost/api/v1/branding'),
    json: async () => {
      if (body === undefined) throw new SyntaxError('no body');
      return body;
    },
  };
}

function params(asset: string) {
  return { params: Promise.resolve({ asset }) };
}

function multipart(asset: string, data: Buffer, name = 'logo.png', type = 'image/png'): NextRequest {
  const form = new FormData();
  form.set('file', new File([new Uint8Array(data)], name, { type }));
  return new NextRequest(`http://localhost/api/v1/branding/assets/${asset}`, { method: 'PUT', body: form });
}

function raw(asset: string, data: Buffer, type: string): NextRequest {
  return new NextRequest(`http://localhost/api/v1/branding/assets/${asset}`, {
    method: 'PUT', body: new Uint8Array(data), headers: { 'content-type': type },
  });
}

async function put(body: unknown) {
  const response = await PUT(jsonRequest('PUT', body));
  return { status: response.status, data: await response.json() };
}

async function upload(asset: string, request: NextRequest) {
  const response = await PUT_ASSET(request, params(asset));
  return { status: response.status, data: await response.json() };
}

function image(asset: string, init: { v?: string; etag?: string } = {}) {
  const url = new URL(`http://localhost/api/branding/${asset}`);
  if (init.v) url.searchParams.set('v', init.v);
  return GET_IMAGE(new NextRequest(url, { headers: init.etag ? { 'if-none-match': init.etag } : {} }), params(asset));
}

/** An element inside the provider the root layout sets up, with the branding in effect. */
function branded(element: ReturnType<typeof createElement>) {
  return createElement(BrandingProvider, { value: toPublicBranding(getBranding()), children: element });
}

function versionOf(url: string): string {
  return new URL(url, 'http://localhost').searchParams.get('v')!;
}

function emptyPayload(): SyncPayload {
  return {
    generated_at: new Date().toISOString(),
    settings: {
      general: null, acme: null, cloudflare: null, dns_provider: null, authentik: null, metrics: null, logging: null,
      dns: null, upstream_dns_resolution: null, waf: null, geoblock: null, error_pages: null, trusted_proxies: null,
    },
    data: { certificates: [], caCertificates: [], issuedClientCertificates: [], accessLists: [], accessListEntries: [], proxyHosts: [], l4ProxyHosts: [] },
  };
}

const BRANDED = {
  productName: 'Example Edge',
  accentColor: '#1d4ed8',
  loginHeading: 'Sign in to Example Edge',
  loginFooter: 'Managed by Example IT.',
  supportUrl: 'https://support.example.com/',
  supportEmail: 'help@example.com',
  emailSenderName: 'Example Alerts',
};

beforeEach(async () => {
  // A background refresh the previous test started must not land in this one's cache.
  await cachedValuesSettled();
  ctx.db = createTestDb();
  await disableForeignKeys(ctx.db);
  resetBrandingCache();
  vi.mocked(logAuditEvent).mockClear();
  vi.mocked(revalidatePath).mockClear();
  mail.sendMail.mockReset();
  delete process.env.INSTANCE_MODE;
});

afterAll(() => {
  resetBrandingCache();
});

describe('GET /api/v1/branding', () => {
  it('shows the defaults', async () => {
    const response = await GET(jsonRequest('GET'));
    const data = (await response.json()) as BrandingView;
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(data).toMatchObject({
      source: 'default',
      defaultProductName: 'Ingressi',
      effective: { productName: 'Ingressi', loginHeading: 'Ingressi', accent: null, poweredByShown: false },
      assets: { logoLight: null, logoDark: null, favicon: null },
      settings: { productName: null, showPoweredBy: true },
    });
  });

  it('requires an administrator (or a role with branding:read)', async () => {
    vi.mocked(requireApiAdmin).mockRejectedValueOnce(new ApiAuthError('Administrator privileges required', 403));
    expect((await GET(jsonRequest('GET'))).status).toBe(403);
  });
});

describe('permissions', () => {
  it('has an instance-wide branding area whose write permission is administrator-level', () => {
    expect(PERMISSION_AREAS.branding).toMatchObject({ actions: ['read', 'write'], instanceWide: true });
    expect(isAdminLevel(['branding:write'])).toBe(true);
    expect(isAdminLevel(['branding:read'])).toBe(false);
  });

  it('refuses changes without branding:write', async () => {
    vi.mocked(requireApiAdmin).mockRejectedValue(new ApiAuthError('Permission required: branding:write', 403));
    try {
      expect((await put({ productName: 'Example Edge' })).status).toBe(403);
      expect((await upload('logo-light', multipart('logo-light', makePng()))).status).toBe(403);
      expect((await DELETE(jsonRequest('DELETE'))).status).toBe(403);
      expect((await DELETE_ASSET(jsonRequest('DELETE'), params('logo-light'))).status).toBe(403);
    } finally {
      vi.mocked(requireApiAdmin).mockReset();
      vi.mocked(requireApiAdmin).mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' });
    }
    expect(await row(WHITE_LABEL_SETTING_KEY)).toBeUndefined();
  });
});

describe('changes', () => {
  it('sets branding up and audits it', async () => {
    const { status, data } = await put(BRANDED);
    expect(status).toBe(200);
    expect(data).toMatchObject({
      source: 'local',
      settings: BRANDED,
      effective: { productName: 'Example Edge', emailSenderName: 'Example Alerts', poweredByShown: true },
    });
    // #1d4ed8 is too dark for the dark theme, so a lighter shade is derived for it.
    expect(data.effective.accent).toEqual({
      light: { color: '#1d4ed8', foreground: '#ffffff' },
      dark: { color: deriveDarkAccent('#1d4ed8'), foreground: foregroundFor(deriveDarkAccent('#1d4ed8')) },
    });
    expect(data.effective.accent.dark.color).not.toBe('#1d4ed8');
    expect(getBranding().productName).toBe('Example Edge');
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({
      userId: 1,
      action: 'branding_updated',
      entityType: 'branding',
      data: expect.objectContaining({ changed: expect.arrayContaining(['productName', 'accentColor']) }),
    }));
  });

  it('restores defaults, removes images and resets', async () => {
    expect((await put({ ...BRANDED, showPoweredBy: false })).status).toBe(200);
    expect((await upload('logo-light', multipart('logo-light', makePng()))).status).toBe(200);
    expect(getBranding().productName).toBe('Example Edge');

    const restored = await put({ ...BRANDED, showPoweredBy: true, supportUrl: null });
    expect(restored.status).toBe(200);
    expect(restored.data.settings).toMatchObject({ showPoweredBy: true, supportUrl: null, productName: 'Example Edge' });

    const removed = await DELETE_ASSET(jsonRequest('DELETE'), params('logo-light'));
    expect(removed.status).toBe(200);
    expect((await removed.json()).assets.logoLight).toBeNull();
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'branding_asset_deleted' }));

    const reset = await DELETE(jsonRequest('DELETE'));
    expect(reset.status).toBe(200);
    expect((await reset.json()).source).toBe('default');
    expect(await row(WHITE_LABEL_SETTING_KEY)).toBeUndefined();
    expect(getBranding()).toBe(DEFAULT_BRANDING);
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'branding_reset' }));
  });
});

describe('validation', () => {
  it('refuses invalid input with 400 and stores nothing', async () => {
    for (const body of [
      { accentColor: '#fff' },
      { accentColor: 'red;}body{display:none' },
      { productName: 'Example‮egdE' },
      { supportUrl: 'javascript:alert(1)' },
      { unknown: true },
      { accentColorDark: '#60a5fa' },
    ]) {
      const response = await put(body);
      expect(response.status, JSON.stringify(body)).toBe(400);
    }
    expect((await PUT({ ...jsonRequest('PUT'), json: async () => { throw new SyntaxError('x'); } })).status).toBe(400);
    expect(await row(WHITE_LABEL_SETTING_KEY)).toBeUndefined();
  });
});

describe('uploads', () => {
  it('stores a PNG without its metadata and serves it with safe headers', async () => {
    const png = makePng(40, 20, [textChunk('Author', 'someone')]);
    const { status, data } = await upload('logo-light', multipart('logo-light', png));
    expect(status).toBe(200);
    expect(data.assets.logoLight).toMatchObject({ type: 'image/png', width: 40, height: 20 });
    expect(data.assets.logoLight.url).toMatch(/^\/api\/branding\/logo-light\?v=[0-9a-f]{16}$/);
    expect(logAuditEvent).toHaveBeenCalledWith(expect.objectContaining({ action: 'branding_asset_uploaded' }));

    const v = versionOf(data.assets.logoLight.url);
    const response = await image('logo-light', { v });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('image/png');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('content-security-policy')).toBe("default-src 'none'; frame-ancestors 'none'; sandbox");
    expect(response.headers.get('cache-control')).toBe('public, max-age=31536000, immutable');
    const body = Buffer.from(await response.arrayBuffer());
    expect(body.subarray(1, 4).toString()).toBe('PNG');
    expect(body.toString('latin1')).not.toContain('someone');

    // Without the current version: revalidate, then 304 for the same ETag.
    const unversioned = await image('logo-light');
    expect(unversioned.headers.get('cache-control')).toBe('no-cache');
    const etag = unversioned.headers.get('etag')!;
    expect((await image('logo-light', { etag })).status).toBe(304);
  });

  it('accepts the image as the body and a new upload changes the version', async () => {
    const first = await upload('logo-dark', raw('logo-dark', makeJpeg(10, 5), 'image/jpeg'));
    expect(first.status).toBe(200);
    expect(first.data.assets.logoDark).toMatchObject({ type: 'image/jpeg', width: 10, height: 5 });
    const second = await upload('logo-dark', raw('logo-dark', makePng(3, 3), 'image/png'));
    expect(versionOf(second.data.assets.logoDark.url)).not.toBe(versionOf(first.data.assets.logoDark.url));
    // The old version is no longer cacheable for long.
    expect((await image('logo-dark', { v: versionOf(first.data.assets.logoDark.url) })).headers.get('cache-control')).toBe('no-cache');
  });

  it('accepts an ICO favicon and links it from every page', async () => {
    const { status, data } = await upload('favicon', raw('favicon', makeIco([{ png: makePng(32, 32), size: 32 }]), 'image/x-icon'));
    expect(status).toBe(200);
    expect(data.assets.favicon).toMatchObject({ type: 'image/x-icon', width: 32, height: 32 });
    expect((await generateMetadata()).icons).toEqual({ icon: [{ url: data.assets.favicon.url, type: 'image/x-icon' }] });
    expect((await image('favicon', { v: versionOf(data.assets.favicon.url) })).headers.get('content-type')).toBe('image/x-icon');
  });

  it.each([
    ['an SVG', () => multipart('logo-light', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), 'logo.svg', 'image/svg+xml'), 400, /SVG/],
    ['an SVG sent as the body', () => raw('logo-light', Buffer.from('<?xml version="1.0"?><svg/>'), 'image/svg+xml'), 400, /SVG/],
    ['a PNG named .svg', () => multipart('logo-light', makePng(), 'logo.svg', 'image/png'), 400, /SVG files are not accepted/],
    ['a PNG/HTML polyglot', () => multipart('logo-light', Buffer.concat([makePng(), Buffer.from('<html><script>x</script></html>')])), 400, /embedded HTML or script/],
    ['an ICO as a logo', () => raw('logo-light', makeIco([{ png: makePng(16, 16), size: 16 }]), 'image/x-icon'), 400, /ICO images are not accepted here/],
    ['a file over 512 KB', () => raw('logo-light', Buffer.concat([makePng(), Buffer.alloc(600 * 1024)]), 'image/png'), 413, /larger than 512 KB/],
    ['a form without a file', () => new NextRequest('http://localhost/x', { method: 'PUT', body: new FormData() }), 400, /"file" field/],
  ])('refuses %s', async (_name, build, status, message) => {
    const response = await upload('logo-light', build());
    expect(response.status).toBe(status);
    expect(response.data.error).toMatch(message);
    expect(await row(WHITE_LABEL_SETTING_KEY)).toBeUndefined();
  });

  it('answers 404 for an unknown asset', async () => {
    expect((await upload('logo', multipart('logo', makePng()))).status).toBe(404);
    expect((await DELETE_ASSET(jsonRequest('DELETE'), params('../etc'))).status).toBe(404);
    const response = await image('../../settings');
    expect(response.status).toBe(404);
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });
});

describe('public image route', () => {
  it('answers 404 with nosniff when no image is set', async () => {
    const response = await image('logo-light');
    expect(response.status).toBe(404);
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('is reachable before sign-in, without the page policy', async () => {
    const response = await middleware(new NextRequest('http://localhost:3000/api/branding/logo-light?v=1'));
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('content-security-policy')).toBeNull();
    // Dashboard pages still redirect to the login page.
    const page = await middleware(new NextRequest('http://localhost:3000/branding'));
    const location = new URL(page.headers.get('location')!);
    expect(location.pathname).toBe('/login');
    expect(location.searchParams.get('next')).toBe('/branding');
  });
});

describe('dashboard actions', () => {
  it('save, upload, remove and reset, revalidating every page', async () => {
    const saved = await saveBrandingAction({ productName: 'Example Edge' });
    expect(saved).toMatchObject({ ok: true, view: { effective: { productName: 'Example Edge' } } });
    expect(revalidatePath).toHaveBeenCalledWith('/', 'layout');

    const form = new FormData();
    form.set('file', new File([new Uint8Array(makePng())], 'logo.png', { type: 'image/png' }));
    expect(await uploadBrandingAssetAction('logo-light', form)).toMatchObject({ ok: true, view: { assets: { logoLight: { type: 'image/png' } } } });
    expect(await uploadBrandingAssetAction('nope', form)).toEqual({ ok: false, error: 'Unknown asset' });

    const svg = new FormData();
    svg.set('file', new File(['<svg/>'], 'logo.svg', { type: 'image/svg+xml' }));
    expect(await uploadBrandingAssetAction('logo-dark', svg)).toMatchObject({ ok: false, error: expect.stringMatching(/SVG/) });

    expect(await deleteBrandingAssetAction('logo-light')).toMatchObject({ ok: true, view: { assets: { logoLight: null } } });
    expect(await resetBrandingAction()).toMatchObject({ ok: true, view: { source: 'default' } });
  });
});

describe('cache', () => {
  it('reuses the parsed branding until it changes', async () => {
    await put({ productName: 'Example Edge' });
    const first = getBranding();
    expect(getBranding()).toBe(first);
    await put({ productName: 'Example Edge 2' });
    expect(getBranding()).not.toBe(first);
    expect(getBranding().productName).toBe('Example Edge 2');
  });

  it('picks up a change written by something else when it is read again', async () => {
    await put({ productName: 'Example Edge' });
    expect(getBranding().productName).toBe('Example Edge');
    await setRow(WHITE_LABEL_SETTING_KEY, { productName: 'Restored Name', showPoweredBy: true }, '2099-01-01T00:00:00.000Z');
    // Requests read the branding from memory: unchanged until it is read again.
    expect(getBranding().productName).toBe('Example Edge');
    await refreshBranding();
    expect(getBranding().productName).toBe('Restored Name');
  });

  it('reads it again in the background once it is older than 30 seconds', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(new Date('2030-01-01T00:00:00.000Z'));
      await setRow(WHITE_LABEL_SETTING_KEY, { productName: 'One' });
      await refreshBranding();
      const one = getBranding();
      vi.setSystemTime(new Date('2030-01-01T00:00:31.000Z'));
      // Unchanged rows: the refresh keeps the parsed branding.
      expect(getBranding()).toBe(one);
      await cachedValuesSettled();
      expect(getBranding()).toBe(one);
      await setRow(WHITE_LABEL_SETTING_KEY, { productName: 'Two' });
      vi.setSystemTime(new Date('2030-01-01T00:01:10.000Z'));
      expect(getBranding().productName).toBe('One');
      await cachedValuesSettled();
      expect(getBranding().productName).toBe('Two');
    } finally {
      vi.useRealTimers();
    }
  });

  it('is read in full by refreshBranding, even when updated_at did not change', async () => {
    const stamp = '2030-01-01T00:00:00.000Z';
    await setRow(WHITE_LABEL_SETTING_KEY, { productName: 'One' }, stamp);
    await refreshBranding();
    expect(getBranding().productName).toBe('One');
    await setRow(WHITE_LABEL_SETTING_KEY, { productName: 'Two' }, stamp);
    expect(getBranding().productName).toBe('One');
    await refreshBranding();
    expect(getBranding().productName).toBe('Two');
  });

  it('falls back to the default branding when the database cannot be read', async () => {
    const working = ctx.db;
    ctx.db = { select: () => { throw new Error('database is locked'); } } as unknown as TestDb;
    try {
      expect(getBranding()).toBe(DEFAULT_BRANDING);
      // Write paths read it themselves and see the failure; a refresh only logs it.
      await expect(loadBranding()).rejects.toThrow('database is locked');
      await expect(refreshBranding()).resolves.toBe(DEFAULT_BRANDING);
      expect(getBranding()).toBe(DEFAULT_BRANDING);
    } finally {
      ctx.db = working;
    }
  });

  it('drops stored values that do not validate', async () => {
    await setRow(WHITE_LABEL_SETTING_KEY, {
      productName: 'Example Edge',
      accentColor: '#000;}</style><script>alert(1)</script>',
      supportUrl: 'javascript:alert(1)',
      assets: { logoLight: { type: 'image/png', data: Buffer.from('<svg onload=alert(1)>').toString('base64') } },
    });
    await refreshBranding();
    const branding = getBranding();
    expect(branding.productName).toBe('Example Edge');
    expect(branding.accent).toBeNull();
    expect(branding.settings.supportUrl).toBeNull();
    expect(branding.assets.logoLight).toBeNull();
    expect(brandingThemeCss(branding)).toBeNull();
  });
});

describe('instance sync', () => {
  it('sends the branding with its images to slaves', async () => {
    await put({ productName: 'Example Edge' });
    await upload('logo-light', multipart('logo-light', makePng(6, 6)));
    const payload = await buildSyncPayload();
    expect(payload.settings.white_label).toMatchObject({ productName: 'Example Edge', assets: { logoLight: { type: 'image/png' } } });
  });

  it('sends the current branding with a promoted fleet revision, which does not hold it', async () => {
    await put({ productName: 'Example Edge' });
    const payload = await buildSyncPayloadFromContent(emptyConfigContent());
    expect(payload.settings.white_label).toMatchObject({ productName: 'Example Edge' });
  });

  it("shows the master's branding on a slave unless the slave has its own", async () => {
    await setRow('instance_mode', 'slave');
    const payload = emptyPayload();
    payload.settings.white_label = {
      productName: 'Master Brand',
      accentColor: '#1d4ed8',
      assets: { logoLight: { type: 'image/png', data: makePng(4, 4).toString('base64') } },
    };
    await refreshBranding(); // load it; applying the payload must read it again
    await applySyncPayload(payload);
    let branding = getBranding();
    expect(branding).toMatchObject({ productName: 'Master Brand', source: 'master' });
    expect(branding.assets.logoLight).toMatchObject({ width: 4, height: 4 });
    expect(toPublicBranding(branding).logoDarkUrl).toBe(toPublicBranding(branding).logoLightUrl);

    await put({ productName: 'Replica Brand' });
    branding = getBranding();
    expect(branding).toMatchObject({ productName: 'Replica Brand', source: 'local' });
    // The local copy started from the master's, logo included.
    expect(branding.assets.logoLight).not.toBeNull();

    await DELETE(jsonRequest('DELETE'));
    expect(getBranding()).toMatchObject({ productName: 'Master Brand', source: 'master' });
  });

  it('validates synced branding like local branding', async () => {
    process.env.INSTANCE_MODE = 'slave';
    const payload = emptyPayload();
    payload.settings.white_label = {
      productName: 'Master‮Brand',
      accentColor: 'expression(alert(1))',
      assets: { favicon: { type: 'image/x-icon', data: Buffer.from('<html>').toString('base64') } },
    };
    await applySyncPayload(payload);
    expect(getBranding()).toBe(DEFAULT_BRANDING);
  });

  it('ignores a synced copy on an instance that is not a slave', async () => {
    await setRow('synced:white_label', { productName: 'Master Brand' });
    await refreshBranding();
    expect(getBranding().productName).toBe('Ingressi');
  });
});

describe('where the branding shows', () => {
  beforeEach(async () => {
    await put({ ...BRANDED, accentColorDark: '#60a5fa' });
    await upload('logo-light', multipart('logo-light', makePng(12, 12)));
  });

  it('page titles and theme colours', async () => {
    expect((await generateMetadata()).title).toEqual({ default: 'Example Edge', template: '%s · Example Edge' });
    expect(brandingThemeCss()).toBe(
      ':root,.dark{--brand-fill:#60a5fa;--on-brand-fill:#000000;--brand:#60a5fa;--brand-tint:color-mix(in srgb,#60a5fa 14%,transparent)}.light{--brand-fill:#1d4ed8;--on-brand-fill:#ffffff;--brand:#1d4ed8;--brand-tint:color-mix(in srgb,#1d4ed8 9%,transparent)}'
    );
  });

  it('the login page', () => {
    const html = renderToStaticMarkup(
      branded(createElement(LoginClient, { enabledProviders: [] }))
    );
    expect(html).toContain('Sign in to Example Edge');
    expect(html).toMatch(/<img src="\/api\/branding\/logo-light\?v=[0-9a-f]{16}" alt="Example Edge"/);
    expect(html).toContain('Managed by Example IT.');
    expect(html).toContain('href="https://support.example.com/"');
    expect(html).toContain('href="mailto:help@example.com"');
    expect(html).toContain('Powered by');
    expect(html).toContain('>Ingressi</a>');
  });

  it('the forward-auth portal', () => {
    const html = renderToStaticMarkup(
      branded(createElement(PortalLoginForm, { rid: 'rid', hasRedirect: true, targetDomain: 'app.example.com', enabledProviders: [] }))
    );
    expect(html).toContain('/api/branding/logo-light?v=');
    expect(html).toContain('Managed by Example IT.');
    expect(html).toContain('help@example.com');
    expect(html).toContain('app.example.com');
  });

  it('the "Powered by" note can be turned off', async () => {
    await put({ showPoweredBy: false });
    expect(toPublicBranding(getBranding()).poweredBy).toBeNull();
  });

  it('e-mails and messages, but not identifiers', async () => {
    const n = testNotification(new Date('2026-10-01T00:00:00.000Z'));
    const email = buildEmail(n);
    expect(email.subject).toMatch(/^\[Example Edge\] /);
    expect(email.text).toContain('Sent by Example Edge');
    expect(email.html).toContain('Sent by Example Edge');
    expect(n.title).toBe('Test notification from Example Edge');
    expect(buildWebhookBody(n).source).toBe('ingressi');
    expect(pagerDutyDedupKey(1, 'x')).toMatch(/^ingressi-1-/);

    mail.sendMail.mockResolvedValue({});
    const channel = {
      id: 1, name: 'Mail', type: 'email', enabled: true,
      config: { host: 'smtp.example.com', port: 465, secure: true, user: null, from: 'alerts@example.com', to: ['ops@example.com'] },
      secrets: {},
    } as never;
    await sendEmailMessage(channel, email);
    expect(mail.sendMail).toHaveBeenCalledWith(expect.objectContaining({ from: { name: 'Example Alerts', address: 'alerts@example.com' } }));
    await put({ emailSenderName: null });
    await sendEmailMessage(channel, email);
    expect(mail.sendMail).toHaveBeenLastCalledWith(expect.objectContaining({ from: 'alerts@example.com' }));
  });

  it('new authenticator app entries', async () => {
    expect(authenticatorIssuer()).toBe('Example Edge');
    await put({ productName: 'Example: Edge' });
    expect(authenticatorIssuer()).not.toContain(':');
  });

  it('the API docs title', async () => {
    const response = await getOpenApi(jsonRequest('GET'));
    const spec = await response.json();
    expect(spec.info.title).toBe('Example Edge API');
    expect(spec.paths['/api/v1/branding'].put.operationId).toBe('updateBranding');
    expect(spec.paths['/api/v1/branding/assets/{asset}'].put.requestBody.content['multipart/form-data']).toBeDefined();
    expect(spec.components.schemas.Branding.required).toEqual(['settings', 'effective', 'assets', 'source', 'updatedAt', 'defaultProductName', 'limits']);
    expect(spec.tags.map((tag: { name: string }) => tag.name)).toContain('White-label');
  });
});
