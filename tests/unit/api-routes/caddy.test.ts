import { describe, it, expect, vi, beforeEach } from 'vitest';

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
    logUnexpectedApiError: vi.fn(() => 'error-id'),
    ApiAuthError,
  };
});

import { POST } from '@/app/api/v1/caddy/apply/route';
import { applyCaddyConfig } from '@/src/lib/caddy';
import { requireApiAdmin } from '@/src/lib/api-auth';

const mockApplyCaddyConfig = vi.mocked(applyCaddyConfig);
const mockRequireApiAdmin = vi.mocked(requireApiAdmin);

function createMockRequest(): any {
  return {
    headers: { get: () => null },
    method: 'POST',
    nextUrl: { pathname: '/api/v1/caddy/apply', searchParams: new URLSearchParams() },
    json: async () => ({}),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockRequireApiAdmin.mockResolvedValue({ userId: 1, role: 'admin', authMethod: 'bearer' });
});

describe('POST /api/v1/caddy/apply', () => {
  it('applies caddy config and returns ok', async () => {
    const response = await POST(createMockRequest());
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ ok: true });
    expect(mockApplyCaddyConfig).toHaveBeenCalled();
  });

  it('answers 502 with why when Caddy does not take the configuration, without claiming anything was saved', async () => {
    const { CaddyApplyError } = await import('@/src/lib/caddy-apply-error');
    const rejection = new CaddyApplyError('Caddy rejected configuration: the problem is in the geoblocking rules', 'CADDY_REJECTED');
    rejection.rejectedAt = 'proxy host a.example.com';
    mockApplyCaddyConfig.mockRejectedValueOnce(rejection);
    const response = await POST(createMockRequest());
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      error: 'Caddy rejected configuration: the problem is in the geoblocking rules (proxy host a.example.com)',
      code: 'CADDY_REJECTED',
    });
  });

  it('returns 401 on auth failure', async () => {
    const { ApiAuthError } = await import('@/src/lib/api-auth');
    mockRequireApiAdmin.mockRejectedValue(new ApiAuthError('Unauthorized', 401));

    const response = await POST(createMockRequest());
    const data = await response.json();

    expect(response.status).toBe(401);
    expect(data.error).toBe('Unauthorized');
  });

  it('returns 500 when applyCaddyConfig fails', async () => {
    mockApplyCaddyConfig.mockRejectedValue(new Error('Connection refused'));

    const response = await POST(createMockRequest());
    const data = await response.json();

    expect(response.status).toBe(500);
    expect(data.error).toBe('Connection refused');
  });
});
