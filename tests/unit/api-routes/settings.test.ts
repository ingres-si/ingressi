import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/src/lib/settings', () => ({
  getGeneralSettings: vi.fn(),
  saveGeneralSettings: vi.fn(),
  getAcmeSettings: vi.fn(),
  saveAcmeSettings: vi.fn(),
  getCloudflareSettings: vi.fn(),
  saveCloudflareSettings: vi.fn(),
  getAuthentikSettings: vi.fn(),
  saveAuthentikSettings: vi.fn(),
  getForwardAuthSettings: vi.fn(),
  saveForwardAuthSettings: vi.fn(),
  getMetricsSettings: vi.fn(),
  saveMetricsSettings: vi.fn(),
  getLoggingSettings: vi.fn(),
  saveLoggingSettings: vi.fn(),
  getDnsSettings: vi.fn(),
  saveDnsSettings: vi.fn(),
  getDnsProviderSettings: vi.fn(),
  saveDnsProviderSettings: vi.fn(),
  getUpstreamDnsResolutionSettings: vi.fn(),
  saveUpstreamDnsResolutionSettings: vi.fn(),
  getGeoBlockSettings: vi.fn(),
  saveGeoBlockSettings: vi.fn(),
  getWafSettings: vi.fn(),
  saveWafSettings: vi.fn(),
  getErrorPagesSettings: vi.fn(),
  saveErrorPagesSettings: vi.fn(),
  getResponseHeadersSettings: vi.fn(),
  saveResponseHeadersSettings: vi.fn(),
  getTrustedProxiesSettings: vi.fn(),
  saveTrustedProxiesSettings: vi.fn(),
  getDefaultResponseSettings: vi.fn(),
  saveDefaultResponseSettings: vi.fn(),
  getRateLimitSettings: vi.fn(),
  saveRateLimitSettings: vi.fn(),
  getSetting: vi.fn(),
  setSetting: vi.fn(),
  clearSetting: vi.fn(),
}));

vi.mock('@/src/lib/instance-sync', () => ({
  getInstanceMode: vi.fn(),
  setInstanceMode: vi.fn(),
  getSlaveMasterToken: vi.fn(),
  setSlaveMasterToken: vi.fn(),
  syncInstances: vi.fn().mockResolvedValue({ total: 0, success: 0, failed: 0, skippedHttp: 0 }),
}));

vi.mock('@/src/lib/auth', () => ({
  requirePermission: vi.fn(() => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireAdmin())),
  requireAdmin: vi.fn().mockResolvedValue({ user: { id: '1' } }),
}));

vi.mock('next/cache', () => ({ revalidatePath: vi.fn() }));
vi.mock('@/src/lib/models/instances', () => ({
  createInstance: vi.fn(),
  deleteInstance: vi.fn(),
  updateInstance: vi.fn(),
}));
vi.mock('@/src/lib/models/proxy-hosts', () => ({
  listProxyHosts: vi.fn(),
  updateProxyHost: vi.fn(),
  sanitizeErrorPageRules: vi.fn((rules: unknown) => rules),
}));
vi.mock('@/src/lib/models/waf-events', () => ({ getWafRuleMessages: vi.fn() }));
// The WAF group snapshots the global exclusion records to put them back if Caddy refuses the change.
vi.mock('@/src/lib/models/waf-exclusion-mirror', () => ({
  readGlobalWafExclusionRows: vi.fn(() => []),
  restoreGlobalWafExclusionRows: vi.fn(),
}));

vi.mock('@/src/lib/caddy', () => ({
  applyCaddyConfig: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock('@/src/lib/api-auth', () => {
  const ApiAuthError = class extends Error {
    status: number;
    constructor(msg: string, status: number) { super(msg); this.status = status; this.name = 'ApiAuthError'; }
  };
  return {
    requireApiPermission: vi.fn((request: unknown) => import('@/tests/helpers/permission-mocks').then((m) => m.viaRequireApiAdmin(request))),
    requireApiAdmin: vi.fn().mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' }),
    requireApiUser: vi.fn().mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' }),
    apiErrorResponse: vi.fn((error: unknown) => {
      const { NextResponse: NR } = require('next/server');
      if (error instanceof ApiAuthError) {
        return NR.json({ error: error.message }, { status: error.status });
      }
      return NR.json({ error: error instanceof Error ? error.message : 'Internal server error' }, { status: 500 });
    }),
    logUnexpectedApiError: vi.fn(() => 'test-error-id'),
    ApiAuthError,
  };
});

import { GET, PUT } from '@/app/api/v1/settings/[group]/route';
import {
  getGeneralSettings, saveGeneralSettings,
  getAcmeSettings, saveAcmeSettings,
  getCloudflareSettings, saveCloudflareSettings,
  getAuthentikSettings, saveAuthentikSettings,
  getForwardAuthSettings, saveForwardAuthSettings,
  getMetricsSettings, saveMetricsSettings,
  getLoggingSettings, saveLoggingSettings,
  getDnsSettings, saveDnsSettings,
  getUpstreamDnsResolutionSettings, saveUpstreamDnsResolutionSettings,
  getGeoBlockSettings, saveGeoBlockSettings,
  getWafSettings, saveWafSettings,
  getTrustedProxiesSettings, saveTrustedProxiesSettings,
  getDefaultResponseSettings, saveDefaultResponseSettings,
  getDnsProviderSettings, saveDnsProviderSettings,
  getSetting, setSetting, clearSetting,
} from '@/src/lib/settings';
import { decryptSecret, isEncryptedSecret } from '@/src/lib/secret';
import { getInstanceMode, setInstanceMode, getSlaveMasterToken, setSlaveMasterToken } from '@/src/lib/instance-sync';
import { applyCaddyConfig } from '@/src/lib/caddy';
import { requireApiAdmin } from '@/src/lib/api-auth';
import { DefaultResponseValidationError } from '@/src/lib/caddy-default-response';
import { updateGeneralSettingsAction, updateRateLimitSettingsAction, updateTrustedProxiesSettingsAction } from '@/app/(dashboard)/settings/actions';
import { saveRateLimitSettings } from '@/src/lib/settings';
import { logAuditEvent } from '@/src/lib/audit';
import { CaddyApplyError } from '@/src/lib/caddy-apply-error';

const mockGetGeneral = vi.mocked(getGeneralSettings);
const mockSaveGeneral = vi.mocked(saveGeneralSettings);
const mockGetAcme = vi.mocked(getAcmeSettings);
const mockSaveAcme = vi.mocked(saveAcmeSettings);
const mockGetCloudflare = vi.mocked(getCloudflareSettings);
const mockSaveCloudflare = vi.mocked(saveCloudflareSettings);
const mockGetAuthentik = vi.mocked(getAuthentikSettings);
const mockSaveAuthentik = vi.mocked(saveAuthentikSettings);
const mockGetForwardAuth = vi.mocked(getForwardAuthSettings);
const mockSaveForwardAuth = vi.mocked(saveForwardAuthSettings);
const mockGetMetrics = vi.mocked(getMetricsSettings);
const mockSaveMetrics = vi.mocked(saveMetricsSettings);
const mockGetLogging = vi.mocked(getLoggingSettings);
const mockSaveLogging = vi.mocked(saveLoggingSettings);
const mockGetDns = vi.mocked(getDnsSettings);
const mockSaveDns = vi.mocked(saveDnsSettings);
const mockGetUpstreamDns = vi.mocked(getUpstreamDnsResolutionSettings);
const mockSaveUpstreamDns = vi.mocked(saveUpstreamDnsResolutionSettings);
const mockGetGeoBlock = vi.mocked(getGeoBlockSettings);
const mockSaveGeoBlock = vi.mocked(saveGeoBlockSettings);
const mockGetWaf = vi.mocked(getWafSettings);
const mockSaveWaf = vi.mocked(saveWafSettings);
const mockGetTrustedProxies = vi.mocked(getTrustedProxiesSettings);
const mockSaveTrustedProxies = vi.mocked(saveTrustedProxiesSettings);
const mockGetDefaultResponse = vi.mocked(getDefaultResponseSettings);
const mockSaveDefaultResponse = vi.mocked(saveDefaultResponseSettings);
const mockGetDnsProvider = vi.mocked(getDnsProviderSettings);
const mockGetSetting = vi.mocked(getSetting);
const mockSetSetting = vi.mocked(setSetting);
const mockClearSetting = vi.mocked(clearSetting);
const mockGetInstanceMode = vi.mocked(getInstanceMode);
const mockSetInstanceMode = vi.mocked(setInstanceMode);
const mockGetSlaveMasterToken = vi.mocked(getSlaveMasterToken);
const mockSetSlaveMasterToken = vi.mocked(setSlaveMasterToken);
const mockApplyCaddyConfig = vi.mocked(applyCaddyConfig);
const mockRequireApiAdmin = vi.mocked(requireApiAdmin);

function createMockRequest(options: { method?: string; body?: unknown } = {}): any {
  return {
    headers: { get: () => null },
    method: options.method ?? 'GET',
    nextUrl: { pathname: '/api/v1/settings/general', searchParams: new URLSearchParams() },
    json: async () => options.body ?? {},
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockRequireApiAdmin.mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' });
  mockGetSetting.mockResolvedValue(null);
  mockGetInstanceMode.mockResolvedValue('standalone');
  mockApplyCaddyConfig.mockResolvedValue({ ok: true } as any);
});

describe('GET /api/v1/settings/[group]', () => {
  it('returns general settings', async () => {
    const settings = { site_name: 'My Proxy', admin_email: 'admin@example.com' };
    mockGetGeneral.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'general' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
  });

  it('returns empty object when settings are null', async () => {
    mockGetGeneral.mockResolvedValue(null as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'general' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({});
  });

  it('returns default response settings', async () => {
    const settings = { mode: 'respond', status: 404, body: 'Not Found' } as const;
    mockGetDefaultResponse.mockResolvedValue(settings);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'default-response' }) });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(settings);
    expect(mockGetDefaultResponse).toHaveBeenCalled();
  });

  it('returns explicit Caddy mode when default response settings are unset', async () => {
    mockGetDefaultResponse.mockResolvedValue(null);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'default-response' }) });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ mode: 'caddy' });
  });

  it('returns only DNS-provider configuration metadata and never credential values', async () => {
    const plaintextSecret = 'dns-plaintext-secret-sentinel';
    const encryptedSecret = 'enc:v1:dns-ciphertext-sentinel';
    mockGetDnsProvider.mockResolvedValue({
      providers: {
        cloudflare: { api_token: plaintextSecret },
        route53: {
          access_key_id: 'access-key-sentinel',
          secret_access_key: encryptedSecret,
          region: 'eu-test-1',
          unused: '',
        },
      },
      default: 'cloudflare',
    });

    const response = await GET(createMockRequest(), {
      params: Promise.resolve({ group: 'dns-provider' }),
    });
    const bodyText = await response.text();
    const data = JSON.parse(bodyText);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(data).toEqual({
      providers: {
        cloudflare: { configuredFields: ['api_token'] },
        route53: {
          configuredFields: ['access_key_id', 'region', 'secret_access_key'],
        },
      },
      default: 'cloudflare',
    });
    expect(bodyText).not.toContain(plaintextSecret);
    expect(bodyText).not.toContain(encryptedSecret);
    expect(bodyText).not.toContain('access-key-sentinel');
    expect(bodyText).not.toContain('eu-test-1');
  });

  it('does not return the legacy Cloudflare API token', async () => {
    mockGetCloudflare.mockResolvedValue({
      apiToken: 'legacy-cloudflare-token-sentinel',
      zoneId: 'zone-id',
      accountId: 'account-id',
    });

    const response = await GET(createMockRequest(), {
      params: Promise.resolve({ group: 'cloudflare' }),
    });
    const bodyText = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(JSON.parse(bodyText)).toEqual({
      hasApiToken: true,
      zoneId: 'zone-id',
      accountId: 'account-id',
    });
    expect(bodyText).not.toContain('legacy-cloudflare-token-sentinel');
    expect(bodyText).not.toContain('apiToken');
  });

  it('returns instance mode', async () => {
    mockGetInstanceMode.mockResolvedValue('standalone' as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'instance-mode' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ mode: 'standalone' });
  });

  it('returns sync-token status', async () => {
    mockGetSlaveMasterToken.mockResolvedValue('some-token' as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'sync-token' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ has_token: true });
  });

  it('returns has_token false when no token', async () => {
    mockGetSlaveMasterToken.mockResolvedValue(null as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'sync-token' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ has_token: false });
  });

  it('returns 404 for unknown settings group', async () => {
    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'unknown' }) });
    const data = await response.json();

    expect(response.status).toBe(404);
    expect(data.error).toBe('Unknown settings group');
  });

  it('returns 401 on auth failure', async () => {
    const { ApiAuthError } = await import('@/src/lib/api-auth');
    mockRequireApiAdmin.mockRejectedValue(new ApiAuthError('Unauthorized', 401));

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'general' }) });
    expect(response.status).toBe(401);
  });
});

describe('PUT /api/v1/settings/[group]', () => {
  it('saves general settings and applies caddy config', async () => {
    mockSaveGeneral.mockResolvedValue(undefined);

    const body = { primaryDomain: 'updated.example.com' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'general' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveGeneral).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });

  it('saves default response settings and applies the Caddy config', async () => {
    const body = {
      mode: 'respond',
      status: 418,
      body: 'CPM_DEFAULT_RESPONSE',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    };
    mockSaveDefaultResponse.mockResolvedValue(undefined);

    const response = await PUT(createMockRequest({ method: 'PUT', body }), {
      params: Promise.resolve({ group: 'default-response' }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(mockSaveDefaultResponse).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });

  it('returns 400 when default response validation fails', async () => {
    mockSaveDefaultResponse.mockRejectedValueOnce(
      new DefaultResponseValidationError('Default response status must be an integer from 200 to 599')
    );

    const response = await PUT(createMockRequest({ method: 'PUT', body: { mode: 'respond', status: 103 } }), {
      params: Promise.resolve({ group: 'default-response' }),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Default response status must be an integer from 200 to 599',
    });
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });

  it('returns 500 when storing default response settings fails', async () => {
    mockSaveDefaultResponse.mockRejectedValueOnce(new Error('database unavailable'));

    const response = await PUT(createMockRequest({ method: 'PUT', body: { mode: 'abort' } }), {
      params: Promise.resolve({ group: 'default-response' }),
    });

    expect(response.status).toBe(500);
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });

  it('sets instance mode', async () => {
    mockSetInstanceMode.mockResolvedValue(undefined as any);

    const body = { mode: 'master' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'instance-mode' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSetInstanceMode).toHaveBeenCalledWith('master');
  });

  it('sets sync token', async () => {
    mockSetSlaveMasterToken.mockResolvedValue(undefined as any);

    const validToken = 'a]b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';
    const body = { token: validToken };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'sync-token' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSetSlaveMasterToken).toHaveBeenCalledWith(validToken);
  });

  it('rejects unknown fields for special settings groups', async () => {
    const modeResponse = await PUT(createMockRequest({
      method: 'PUT',
      body: { mode: 'master', injected: true },
    }), { params: Promise.resolve({ group: 'instance-mode' }) });
    const tokenResponse = await PUT(createMockRequest({
      method: 'PUT',
      body: { token: 'a'.repeat(32), futureSecret: 'sentinel' },
    }), { params: Promise.resolve({ group: 'sync-token' }) });

    expect(modeResponse.status).toBe(400);
    expect(tokenResponse.status).toBe(400);
    expect(mockSetInstanceMode).not.toHaveBeenCalled();
    expect(mockSetSlaveMasterToken).not.toHaveBeenCalled();
  });

  it('rejects oversized special-group credentials before persistence', async () => {
    const response = await PUT(createMockRequest({
      method: 'PUT',
      body: { token: 'a'.repeat(513) },
    }), { params: Promise.resolve({ group: 'sync-token' }) });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Sync token must be at most 512 characters; token must otherwise be null',
    });
    expect(mockSetSlaveMasterToken).not.toHaveBeenCalled();
  });

  it('clears sync token when null', async () => {
    mockSetSlaveMasterToken.mockResolvedValue(undefined as any);

    const body = {};
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'sync-token' }) });
    await response.json();

    expect(response.status).toBe(200);
    expect(mockSetSlaveMasterToken).toHaveBeenCalledWith(null);
  });

  it('returns 404 for unknown settings group', async () => {
    const response = await PUT(createMockRequest({ method: 'PUT', body: {} }), { params: Promise.resolve({ group: 'unknown' }) });
    const data = await response.json();

    expect(response.status).toBe(404);
    expect(data.error).toBe('Unknown settings group');
  });

  it('returns 502 and restores the exact stored value if Caddy rejects the update', async () => {
    const previous = { primaryDomain: 'old.example.com', acmeEmail: 'old@example.com' };
    mockGetSetting.mockResolvedValue(previous);
    mockSaveGeneral.mockResolvedValue(undefined);
    mockApplyCaddyConfig
      .mockRejectedValueOnce(new Error('caddy rejected secret internal details'))
      .mockResolvedValueOnce({ ok: true } as any);

    const response = await PUT(createMockRequest({ method: 'PUT', body: { primaryDomain: 'new.example.com' } }), { params: Promise.resolve({ group: 'general' }) });
    const data = await response.json();

    expect(response.status).toBe(502);
    expect(data).toEqual({ error: 'Failed to apply Caddy configuration; settings were rolled back' });
    expect(JSON.stringify(data)).not.toContain('secret internal details');
    expect(mockSetSetting).toHaveBeenCalledWith('general', previous);
    expect(mockApplyCaddyConfig).toHaveBeenCalledTimes(2);
  });

  it('clears a newly created setting if its first Caddy apply fails', async () => {
    mockGetSetting.mockResolvedValue(null);
    mockApplyCaddyConfig.mockRejectedValueOnce(new Error('caddy down'));

    const response = await PUT(createMockRequest({ method: 'PUT', body: { enabled: true, port: 9090 } }), {
      params: Promise.resolve({ group: 'metrics' }),
    });

    expect(response.status).toBe(502);
    expect(mockClearSetting).toHaveBeenCalledWith('metrics');
  });

  it('reports a rollback failure instead of claiming the settings were restored', async () => {
    mockGetSetting.mockResolvedValue({ enabled: false, port: 9090 });
    mockApplyCaddyConfig.mockRejectedValueOnce(new Error('caddy down'));
    mockSetSetting.mockRejectedValueOnce(new Error('database unavailable'));

    const response = await PUT(createMockRequest({ method: 'PUT', body: { enabled: true, port: 9090 } }), {
      params: Promise.resolve({ group: 'metrics' }),
    });

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      error: 'Failed to apply Caddy configuration and roll back settings',
    });
  });

  it('serializes updates so a failing rollback cannot overwrite a concurrent success', async () => {
    let rejectFirstApply!: (reason: Error) => void;
    const firstApply = new Promise<never>((_resolve, reject) => {
      rejectFirstApply = reject;
    });
    mockGetSetting.mockResolvedValue({ primaryDomain: 'old.example.com' });
    mockSaveGeneral.mockResolvedValue(undefined);
    mockApplyCaddyConfig
      .mockImplementationOnce(() => firstApply)
      .mockResolvedValueOnce({ ok: true } as any)
      .mockResolvedValueOnce({ ok: true } as any);

    const first = PUT(createMockRequest({
      method: 'PUT',
      body: { primaryDomain: 'first.example.com' },
    }), { params: Promise.resolve({ group: 'general' }) });
    await vi.waitFor(() => expect(mockApplyCaddyConfig).toHaveBeenCalledTimes(1));

    const second = PUT(createMockRequest({
      method: 'PUT',
      body: { primaryDomain: 'second.example.com' },
    }), { params: Promise.resolve({ group: 'general' }) });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(mockSaveGeneral).toHaveBeenCalledTimes(1);
    rejectFirstApply(new Error('first apply failed'));

    expect((await first).status).toBe(502);
    expect((await second).status).toBe(200);
    expect(mockSaveGeneral).toHaveBeenNthCalledWith(2, {
      primaryDomain: 'second.example.com',
    });
    expect(mockApplyCaddyConfig).toHaveBeenCalledTimes(3);
  });

  it('shares the rollback lock with dashboard settings actions', async () => {
    let rejectApiApply!: (reason: Error) => void;
    const apiApply = new Promise<never>((_resolve, reject) => {
      rejectApiApply = reject;
    });
    mockGetSetting.mockResolvedValue({ primaryDomain: 'old.example.com' });
    mockSaveGeneral.mockResolvedValue(undefined);
    mockApplyCaddyConfig
      .mockImplementationOnce(() => apiApply)
      .mockResolvedValueOnce({ ok: true } as any);

    const apiUpdate = PUT(createMockRequest({
      method: 'PUT',
      body: { primaryDomain: 'api.example.com' },
    }), { params: Promise.resolve({ group: 'general' }) });
    await vi.waitFor(() => expect(mockApplyCaddyConfig).toHaveBeenCalledTimes(1));

    const formData = new FormData();
    formData.set('primaryDomain', 'dashboard.example.com');
    const dashboardUpdate = updateGeneralSettingsAction(null, formData);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(mockSaveGeneral).toHaveBeenCalledTimes(1);
    rejectApiApply(new Error('API apply failed'));

    expect((await apiUpdate).status).toBe(502);
    expect(await dashboardUpdate).toMatchObject({ success: true });
    expect(mockSaveGeneral).toHaveBeenNthCalledWith(2, {
      primaryDomain: 'dashboard.example.com',
      acmeEmail: undefined,
    });
  });

  it('rejects unknown settings fields before persistence or Caddy apply', async () => {
    const response = await PUT(createMockRequest({
      method: 'PUT',
      body: { enabled: true, port: 9090, injected: { handler: 'exec' } },
    }), { params: Promise.resolve({ group: 'metrics' }) });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'metrics settings contains unknown field: injected' });
    expect(mockSaveMetrics).not.toHaveBeenCalled();
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });
});

describe('GET acme settings', () => {
  it('returns acme settings', async () => {
    const settings = { caUrl: 'https://ca.internal.example.com/acme/acme/directory' };
    mockGetAcme.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'acme' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetAcme).toHaveBeenCalled();
  });
});

describe('PUT acme settings', () => {
  it('saves acme settings and applies caddy config', async () => {
    mockSaveAcme.mockResolvedValue(undefined);

    const body = { caUrl: 'https://ca.internal.example.com/acme/acme/directory' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'acme' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveAcme).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET cloudflare settings', () => {
  it('returns non-secret Cloudflare settings metadata', async () => {
    const settings = { apiToken: 'cf-token-xxx', zoneId: 'zone123', accountId: 'acc456' };
    mockGetCloudflare.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'cloudflare' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ hasApiToken: true, zoneId: 'zone123', accountId: 'acc456' });
    expect(mockGetCloudflare).toHaveBeenCalled();
  });
});

describe('PUT cloudflare settings', () => {
  it('saves cloudflare settings and applies caddy config', async () => {
    mockSaveCloudflare.mockResolvedValue(undefined);

    const body = { apiToken: 'new-token' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'cloudflare' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveCloudflare).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET authentik settings', () => {
  it('returns authentik settings', async () => {
    const settings = { outpostDomain: 'auth.example.com', outpostUpstream: 'http://authentik:9000', authEndpoint: '/outpost.goauthentik.io/auth/caddy' };
    mockGetAuthentik.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'authentik' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetAuthentik).toHaveBeenCalled();
  });
});

describe('PUT authentik settings', () => {
  it('saves authentik settings and applies caddy config', async () => {
    mockSaveAuthentik.mockResolvedValue(undefined);

    const body = { outpostDomain: 'auth.example.com', outpostUpstream: 'http://authentik:9000', authEndpoint: '/outpost.goauthentik.io/auth/caddy' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'authentik' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveAuthentik).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET forward-auth settings', () => {
  it('returns forward auth settings', async () => {
    const settings = { provider: 'authelia', authUpstream: 'http://authelia:9091', authEndpoint: '/api/authz/forward-auth' };
    mockGetForwardAuth.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'forward-auth' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetForwardAuth).toHaveBeenCalled();
  });
});

describe('PUT forward-auth settings', () => {
  it('saves forward auth settings without applying caddy config', async () => {
    mockSaveForwardAuth.mockResolvedValue(undefined);
    mockApplyCaddyConfig.mockClear();

    const body = { provider: 'authelia', authUpstream: 'http://authelia:9091' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'forward-auth' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveForwardAuth).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });

  it('rejects unknown fields for forward auth settings', async () => {
    const body = { provider: 'authelia', authUpstream: 'http://authelia:9091', evil: true };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'forward-auth' }) });

    expect(response.status).toBe(400);
    expect(mockSaveForwardAuth).not.toHaveBeenCalled();
  });

  it('rejects a non-http upstream URL', async () => {
    const body = { provider: 'authelia', authUpstream: 'not-a-url' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'forward-auth' }) });

    expect(response.status).toBe(400);
    expect(mockSaveForwardAuth).not.toHaveBeenCalled();
  });
});

describe('GET metrics settings', () => {
  it('returns metrics settings', async () => {
    const settings = { enabled: true, port: 9090 };
    mockGetMetrics.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'metrics' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetMetrics).toHaveBeenCalled();
  });
});

describe('PUT metrics settings', () => {
  it('saves metrics settings and applies caddy config', async () => {
    mockSaveMetrics.mockResolvedValue(undefined);

    const body = { enabled: false };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'metrics' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveMetrics).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET logging settings', () => {
  it('returns logging settings', async () => {
    const settings = { enabled: true, format: 'json' };
    mockGetLogging.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'logging' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetLogging).toHaveBeenCalled();
  });
});

describe('PUT logging settings', () => {
  it('saves logging settings and applies caddy config', async () => {
    mockSaveLogging.mockResolvedValue(undefined);

    const body = { enabled: true, format: 'console' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'logging' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveLogging).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET dns settings', () => {
  it('returns dns settings', async () => {
    const settings = { enabled: true, resolvers: ['1.1.1.1', '8.8.8.8'], fallbacks: ['9.9.9.9'], timeout: '5s' };
    mockGetDns.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'dns' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetDns).toHaveBeenCalled();
  });
});

describe('PUT dns settings', () => {
  it('saves dns settings and applies caddy config', async () => {
    mockSaveDns.mockResolvedValue(undefined);

    const body = { enabled: true, resolvers: ['1.1.1.1', '8.8.8.8'], fallbacks: ['9.9.9.9'], timeout: '5s' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'dns' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveDns).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET upstream-dns settings', () => {
  it('returns upstream-dns settings', async () => {
    const settings = { enabled: true, family: 'ipv4' };
    mockGetUpstreamDns.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'upstream-dns' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetUpstreamDns).toHaveBeenCalled();
  });
});

describe('PUT upstream-dns settings', () => {
  it('saves upstream-dns settings and applies caddy config', async () => {
    mockSaveUpstreamDns.mockResolvedValue(undefined);

    const body = { enabled: true, family: 'both' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'upstream-dns' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveUpstreamDns).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET geoblock settings', () => {
  it('returns geoblock settings', async () => {
    const settings = {
      enabled: true,
      block_countries: ['CN'],
      block_continents: [],
      block_asns: [],
      block_cidrs: [],
      block_ips: [],
      allow_countries: ['FI'],
      allow_continents: [],
      allow_asns: [],
      allow_cidrs: [],
      allow_ips: [],
      trusted_proxies: ['private_ranges'],
      fail_closed: false,
      response_status: 403,
      response_body: 'Forbidden',
      response_headers: {},
      redirect_url: '',
    };
    mockGetGeoBlock.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'geoblock' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetGeoBlock).toHaveBeenCalled();
  });
});

describe('PUT geoblock settings', () => {
  it('saves geoblock settings and applies caddy config', async () => {
    mockSaveGeoBlock.mockResolvedValue(undefined);

    const body = {
      enabled: true,
      block_countries: ['CN'],
      block_continents: [],
      block_asns: [],
      block_cidrs: [],
      block_ips: [],
      allow_countries: ['FI'],
      allow_continents: [],
      allow_asns: [],
      allow_cidrs: [],
      allow_ips: [],
      trusted_proxies: ['private_ranges'],
      fail_closed: false,
      response_status: 403,
      response_body: 'Forbidden',
      response_headers: {},
      redirect_url: '',
    };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'geoblock' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveGeoBlock).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('GET waf settings', () => {
  it('returns waf settings', async () => {
    const settings = { enabled: true, mode: 'On', load_owasp_crs: true, custom_directives: '', excluded_rule_ids: [920350] };
    mockGetWaf.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'waf' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetWaf).toHaveBeenCalled();
  });
});

describe('PUT dns-provider settings', () => {
  it('stores provider credentials encrypted', async () => {
    const mockSaveDnsProvider = vi.mocked(saveDnsProviderSettings);
    mockSaveDnsProvider.mockResolvedValue(undefined);

    const body = { providers: { cloudflare: { api_token: 'plain-cloudflare-token' } }, default: 'cloudflare' };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'dns-provider' }) });

    expect(response.status).toBe(200);
    const token = mockSaveDnsProvider.mock.calls.at(-1)?.[0]?.providers.cloudflare?.api_token ?? '';
    expect(isEncryptedSecret(token)).toBe(true);
    expect(decryptSecret(token)).toBe('plain-cloudflare-token');
  });
});

describe('PUT waf settings', () => {
  it('saves waf settings and applies caddy config', async () => {
    mockSaveWaf.mockResolvedValue(undefined);

    const body = { enabled: true, mode: 'On', load_owasp_crs: true, custom_directives: '', excluded_rule_ids: [920350] };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'waf' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    // The caller is the author of exclusion records the excluded_rule_ids list adds.
    expect(mockSaveWaf).toHaveBeenCalledWith(body, { actorUserId: 1 });
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });

  it('keeps accepting a stored directive the filter now drops, but rejects a newly added one', async () => {
    const legacy = 'SecRule ARGS "@pmFromFile /etc/hosts" "id:1,deny"';
    mockGetWaf.mockResolvedValue({ enabled: true, mode: 'On', load_owasp_crs: true, custom_directives: legacy, excluded_rule_ids: [] } as any);
    mockSaveWaf.mockResolvedValue(undefined);

    const unchanged = { enabled: true, mode: 'DetectionOnly', load_owasp_crs: true, custom_directives: legacy, excluded_rule_ids: [] };
    const ok = await PUT(createMockRequest({ method: 'PUT', body: unchanged }), { params: Promise.resolve({ group: 'waf' }) });
    expect(ok.status).toBe(200);
    expect(mockSaveWaf).toHaveBeenCalledWith(unchanged, { actorUserId: 1 });

    mockSaveWaf.mockClear();
    const added = 'SecRule ARGS "@ipMatchFromFile /etc/blocklist" "id:2,deny"';
    const body = { ...unchanged, custom_directives: `${legacy}\n${added}` };
    const rejected = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'waf' }) });
    const data = await rejected.json();
    expect(rejected.status).toBe(400);
    expect(data.error).toContain(added);
    expect(data.error).not.toContain('/etc/hosts');
    expect(mockSaveWaf).not.toHaveBeenCalled();
  });
});

describe('GET trusted-proxies settings', () => {
  it('returns trusted-proxies settings', async () => {
    const settings = { ranges: ['172.21.0.1/32'], client_ip_headers: ['Cf-Connecting-Ip'], strict: true, default_geoblock: false };
    mockGetTrustedProxies.mockResolvedValue(settings as any);

    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'trusted-proxies' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual(settings);
    expect(mockGetTrustedProxies).toHaveBeenCalled();
  });
});

describe('PUT trusted-proxies settings', () => {
  it('saves trusted-proxies settings and applies caddy config', async () => {
    mockSaveTrustedProxies.mockResolvedValue(undefined);

    const body = { ranges: ['private_ranges'], default_geoblock: true };
    const response = await PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'trusted-proxies' }) });
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockSaveTrustedProxies).toHaveBeenCalledWith(body);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });
});

describe('PUT trusted-proxies settings: PROXY protocol sources', () => {
  const put = (body: unknown) =>
    PUT(createMockRequest({ method: 'PUT', body }), { params: Promise.resolve({ group: 'trusted-proxies' }) });

  it('stores the sources normalized and applies Caddy', async () => {
    mockSaveTrustedProxies.mockResolvedValue(undefined);
    const response = await put({ ranges: [], proxy_protocol_ranges: ['192.168.1.1/24', ' 10.0.0.5 ', '10.0.0.5', '2001:db8::1'] });
    expect(response.status).toBe(200);
    expect(mockSaveTrustedProxies).toHaveBeenCalledWith({ ranges: [], proxy_protocol_ranges: ['192.168.1.0/24', '10.0.0.5', '2001:db8::1'] });
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });

  it('refuses a source that matches every address, without saving or applying', async () => {
    for (const all of ['0.0.0.0/0', '::/0']) {
      const response = await put({ ranges: [], proxy_protocol_ranges: ['192.168.1.1', all] });
      expect(response.status).toBe(400);
      expect((await response.json()).error).toMatch(/proxy_protocol_ranges: .* matches every address/);
    }
    expect(mockSaveTrustedProxies).not.toHaveBeenCalled();
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });

  it('refuses private_ranges, names and non-lists', async () => {
    for (const value of [['private_ranges'], ['firewall.lan'], '192.168.1.1', [7]]) {
      const response = await put({ ranges: [], proxy_protocol_ranges: value });
      expect(response.status, JSON.stringify(value)).toBe(400);
      expect((await response.json()).error).toContain('trusted-proxies.proxy_protocol_ranges');
    }
    expect(mockSaveTrustedProxies).not.toHaveBeenCalled();
  });

  it('rolls the sources back when Caddy rejects the configuration', async () => {
    const previous = { ranges: ['10.0.0.0/8'] };
    mockGetSetting.mockResolvedValueOnce(previous);
    mockSaveTrustedProxies.mockResolvedValue(undefined);
    mockApplyCaddyConfig.mockRejectedValueOnce(new Error('Caddy rejected configuration'));
    const response = await put({ ranges: [], proxy_protocol_ranges: ['192.168.1.1'] });
    expect(response.status).toBe(502);
    expect(mockSetSetting).toHaveBeenCalledWith('trusted_proxies', previous);
  });

  it('returns the stored sources', async () => {
    const settings = { ranges: [], proxy_protocol_ranges: ['192.168.1.1', '10.0.10.0/24'] };
    mockGetTrustedProxies.mockResolvedValue(settings as any);
    const response = await GET(createMockRequest(), { params: Promise.resolve({ group: 'trusted-proxies' }) });
    expect(await response.json()).toEqual(settings);
  });
});

describe('updateTrustedProxiesSettingsAction (dashboard form)', () => {
  const form = (fields: Record<string, string>) => {
    const formData = new FormData();
    for (const [key, value] of Object.entries(fields)) formData.set(key, value);
    return formData;
  };

  it('saves the PROXY protocol sources from the text area, normalized', async () => {
    const result = await updateTrustedProxiesSettingsAction(null, form({
      ranges: '', clientIpHeaders: '', proxyProtocolRanges: '192.168.1.1\n10.0.10.7/24, 192.168.1.1\n\n2001:db8::1',
    }));
    expect(result).toMatchObject({ success: true });
    expect(mockSaveTrustedProxies).toHaveBeenCalledWith({
      ranges: [],
      client_ip_headers: undefined,
      strict: undefined,
      default_geoblock: undefined,
      proxy_protocol_ranges: ['192.168.1.1', '10.0.10.0/24', '2001:db8::1'],
    });
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });

  it('keeps the other fields as they were saved before', async () => {
    await updateTrustedProxiesSettingsAction(null, form({
      ranges: 'private_ranges', clientIpHeaders: 'Cf-Connecting-Ip', strict: 'on', defaultGeoblock: 'on', proxyProtocolRanges: '172.21.0.1',
    }));
    expect(mockSaveTrustedProxies).toHaveBeenCalledWith({
      ranges: ['private_ranges'],
      client_ip_headers: ['Cf-Connecting-Ip'],
      strict: true,
      default_geoblock: true,
      proxy_protocol_ranges: ['172.21.0.1'],
    });
  });

  it('leaves the sources out when the text area is empty or missing', async () => {
    await updateTrustedProxiesSettingsAction(null, form({ ranges: '10.0.0.0/8', proxyProtocolRanges: '  \n ' }));
    expect(mockSaveTrustedProxies).toHaveBeenLastCalledWith(expect.objectContaining({ proxy_protocol_ranges: undefined }));
    await updateTrustedProxiesSettingsAction(null, form({ ranges: '10.0.0.0/8' }));
    expect(mockSaveTrustedProxies).toHaveBeenLastCalledWith(expect.objectContaining({ proxy_protocol_ranges: undefined }));
  });

  it('reports a bad source by name and saves nothing', async () => {
    for (const [text, message] of [
      ['192.168.1.1\n0.0.0.0/0', /PROXY protocol sources: "0\.0\.0\.0\/0" matches every address/],
      ['private_ranges', /PROXY protocol sources: "private_ranges" is not accepted here/],
      ['firewall.lan', /PROXY protocol sources: "firewall\.lan" is not an IP address or a CIDR range/],
    ] as const) {
      const result = await updateTrustedProxiesSettingsAction(null, form({ ranges: '', proxyProtocolRanges: text }));
      expect(result.success).toBe(false);
      expect(result.message).toMatch(message);
    }
    expect(mockSaveTrustedProxies).not.toHaveBeenCalled();
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });
});

describe('updateRateLimitSettingsAction (dashboard form)', () => {
  const form = (value: unknown) => {
    const formData = new FormData();
    formData.set('rateLimitSettingsJson', typeof value === 'string' ? value : JSON.stringify(value));
    return formData;
  };
  const settings = {
    enabled: true,
    rules: [{ path: '/login', methods: ['post'], key: 'client_ip', events: 5, window: '1m' }],
    allowlist: ['192.0.2.1'],
    ipv6Prefix: 64,
  };

  it('saves the normalized settings, applies Caddy and records an audit event', async () => {
    const result = await updateRateLimitSettingsAction(null, form(settings));
    expect(result).toMatchObject({ success: true });
    const saved = {
      enabled: true,
      rules: [{ path: '/login', methods: ['POST'], key: 'client_ip', events: 5, window: '1m' }],
      allowlist: ['192.0.2.1'],
      ipv6Prefix: 64,
    };
    expect(vi.mocked(saveRateLimitSettings)).toHaveBeenCalledWith(saved);
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
    expect(vi.mocked(logAuditEvent)).toHaveBeenCalledWith(expect.objectContaining({
      userId: 1, entityType: 'setting', summary: 'Updated rate limiting defaults', data: saved,
    }));
  });

  it('reports invalid input without saving', async () => {
    expect(await updateRateLimitSettingsAction(null, form('{not json'))).toEqual({ success: false, message: 'Invalid rate limiting payload' });
    const result = await updateRateLimitSettingsAction(null, form({ ...settings, rules: [{ events: 5, window: '1d' }] }));
    expect(result.success).toBe(false);
    expect(result.message).toMatch(/Rate limiting\.rules\[0\]\.window/);
    expect(vi.mocked(saveRateLimitSettings)).not.toHaveBeenCalled();
    expect(mockApplyCaddyConfig).not.toHaveBeenCalled();
  });

  it('restores the previous value when Caddy rejects the configuration', async () => {
    const previous = { enabled: false, rules: [], allowlist: [] };
    mockGetSetting.mockResolvedValueOnce(previous);
    mockApplyCaddyConfig.mockRejectedValueOnce(new CaddyApplyError('Caddy rejected configuration', 'CADDY_REJECTED'));
    const result = await updateRateLimitSettingsAction(null, form(settings));
    expect(result.success).toBe(false);
    expect(mockSetSetting).toHaveBeenCalledWith('rate_limit', previous);
    expect(mockApplyCaddyConfig).toHaveBeenCalledTimes(2);
    expect(vi.mocked(logAuditEvent)).not.toHaveBeenCalled();
  });

  it('clears the setting on rejection when there was none, and keeps it when only syncing failed', async () => {
    mockApplyCaddyConfig.mockRejectedValueOnce(new CaddyApplyError('Caddy rejected configuration', 'CADDY_REJECTED'));
    await updateRateLimitSettingsAction(null, form(settings));
    expect(mockClearSetting).toHaveBeenCalledWith('rate_limit');

    vi.clearAllMocks();
    mockApplyCaddyConfig.mockRejectedValueOnce(new CaddyApplyError('sync failed', 'INSTANCE_SYNC_FAILED'));
    const result = await updateRateLimitSettingsAction(null, form(settings));
    expect(result).toMatchObject({ success: true });
    expect(mockClearSetting).not.toHaveBeenCalled();
    expect(mockSetSetting).not.toHaveBeenCalled();
  });
});
