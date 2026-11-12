import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the api-tokens model
vi.mock('@/src/lib/models/api-tokens', () => ({
  validateToken: vi.fn(),
}));

// Mock next-auth
vi.mock('@/src/lib/auth', () => ({
  auth: vi.fn(),
  checkSameOrigin: vi.fn(() => null),
}));

// The MFA policy gate (src/lib/mfa.ts); reset to "not required" before each test.
vi.mock('@/src/lib/mfa', () => ({
  mfaEnrolmentRequired: vi.fn(),
}));

import { authenticateApiRequest, requireApiUser, requireApiAdmin, ApiAuthError, NotFoundError, apiErrorResponse } from '@/src/lib/api-auth';
import { ApiClientError, ApiConflictError, ApiValidationError } from '@/src/lib/api-errors';
import { CaddyApplyError } from '@/src/lib/caddy-apply-error';
import { validateToken } from '@/src/lib/models/api-tokens';
import { auth, checkSameOrigin } from '@/src/lib/auth';
import { mfaEnrolmentRequired } from '@/src/lib/mfa';
import { NextResponse } from 'next/server';

const mockValidateToken = vi.mocked(validateToken);
const mockAuth = vi.mocked(auth);

function createMockRequest(options: { authorization?: string; method?: string; origin?: string } = {}): any {
  return {
    headers: {
      get(name: string) {
        if (name === 'authorization') return options.authorization ?? null;
        if (name === 'origin') return options.origin ?? null;
        return null;
      },
    },
    method: options.method ?? 'GET',
    nextUrl: { pathname: '/api/v1/test' },
  };
}

beforeEach(() => {
  vi.resetAllMocks();
});

describe('authenticateApiRequest', () => {
  it('authenticates via Bearer token', async () => {
    mockValidateToken.mockResolvedValue({
      token: { id: 1, name: 'test', createdBy: 42, createdAt: '', lastUsedAt: null, expiresAt: null, scopes: null },
      user: { id: 42, role: 'admin' },
    });

    const result = await authenticateApiRequest(createMockRequest({ authorization: 'Bearer test-token' }));

    expect(result.userId).toBe(42);
    expect(result.role).toBe('admin');
    expect(result.authMethod).toBe('bearer');
    expect(mockValidateToken).toHaveBeenCalledWith('test-token');
  });

  it('rejects invalid Bearer token', async () => {
    mockValidateToken.mockResolvedValue(null);

    await expect(
      authenticateApiRequest(createMockRequest({ authorization: 'Bearer bad-token' }))
    ).rejects.toThrow(ApiAuthError);
  });

  it('falls back to session auth when no Bearer header', async () => {
    mockAuth.mockResolvedValue({
      user: { id: '10', role: 'user', name: 'Test', email: 'test@test.com' },
      expires: '',
    } as any);

    const result = await authenticateApiRequest(createMockRequest());

    expect(result.userId).toBe(10);
    expect(result.role).toBe('user');
    expect(result.authMethod).toBe('session');
  });

  it('refuses a session whose account must set up MFA first (403), but not its API tokens', async () => {
    vi.mocked(mfaEnrolmentRequired).mockImplementation(async (userId: number) => userId === 10);
    mockAuth.mockResolvedValue({
      user: { id: '10', role: 'admin', name: 'Test', email: 'test@test.com' },
      expires: '',
    } as any);
    const error = await authenticateApiRequest(createMockRequest()).catch((e) => e);
    expect(error).toBeInstanceOf(ApiAuthError);
    expect(error.status).toBe(403);
    expect(error.message).toMatch(/multi-factor/);

    mockValidateToken.mockResolvedValue({
      token: { id: 1, name: 'test', createdBy: 10, createdAt: '', lastUsedAt: null, expiresAt: null, scopes: null },
      user: { id: 10, role: 'admin' },
    });
    const bearer = await authenticateApiRequest(createMockRequest({ authorization: 'Bearer test-token' }));
    expect(bearer).toMatchObject({ userId: 10, authMethod: 'bearer' });
  });

  it('throws 401 when neither auth method succeeds', async () => {
    mockAuth.mockResolvedValue(null as any);

    await expect(
      authenticateApiRequest(createMockRequest())
    ).rejects.toThrow(ApiAuthError);

    try {
      await authenticateApiRequest(createMockRequest());
    } catch (e) {
      expect((e as ApiAuthError).status).toBe(401);
    }
  });
});

describe('requireApiAdmin', () => {
  it('allows admin users', async () => {
    mockValidateToken.mockResolvedValue({
      token: { id: 1, name: 'test', createdBy: 1, createdAt: '', lastUsedAt: null, expiresAt: null, scopes: null },
      user: { id: 1, role: 'admin' },
    });

    const result = await requireApiAdmin(createMockRequest({ authorization: 'Bearer token' }));
    expect(result.role).toBe('admin');
  });

  it('rejects non-admin users with 403', async () => {
    mockValidateToken.mockResolvedValue({
      token: { id: 1, name: 'test', createdBy: 2, createdAt: '', lastUsedAt: null, expiresAt: null, scopes: null },
      user: { id: 2, role: 'user' },
    });

    try {
      await requireApiAdmin(createMockRequest({ authorization: 'Bearer token' }));
      expect.fail('Should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiAuthError);
      expect((e as ApiAuthError).status).toBe(403);
    }
  });
});

describe('requireApiUser', () => {
  it('returns auth result for valid user', async () => {
    mockAuth.mockResolvedValue({
      user: { id: '5', role: 'viewer', name: 'V', email: 'v@test.com' },
      expires: '',
    } as any);

    const result = await requireApiUser(createMockRequest());
    expect(result.userId).toBe(5);
    expect(result.role).toBe('viewer');
  });

  it('CSRF check blocks session-authenticated POST without same origin', async () => {
    mockAuth.mockResolvedValue({
      user: { id: '5', role: 'user', name: 'U', email: 'u@test.com' },
      expires: '',
    } as any);

    const mockCheckSameOrigin = vi.mocked(checkSameOrigin);
    mockCheckSameOrigin.mockReturnValueOnce(NextResponse.json({ error: 'Forbidden' }, { status: 403 }) as any);

    await expect(
      requireApiUser(createMockRequest({ method: 'POST' }))
    ).rejects.toThrow(ApiAuthError);

    try {
      mockCheckSameOrigin.mockReturnValueOnce(NextResponse.json({ error: 'Forbidden' }, { status: 403 }) as any);
      mockAuth.mockResolvedValue({
        user: { id: '5', role: 'user', name: 'U', email: 'u@test.com' },
        expires: '',
      } as any);
      await requireApiUser(createMockRequest({ method: 'POST' }));
    } catch (e) {
      expect((e as ApiAuthError).status).toBe(403);
    }
  });

  it('CSRF check skips for Bearer-authenticated POST', async () => {
    mockValidateToken.mockResolvedValue({
      token: { id: 1, name: 'test', createdBy: 42, createdAt: '', lastUsedAt: null, expiresAt: null, scopes: null },
      user: { id: 42, role: 'admin' },
    });

    const mockCheckSameOrigin = vi.mocked(checkSameOrigin);
    mockCheckSameOrigin.mockReturnValueOnce(NextResponse.json({ error: 'Forbidden' }, { status: 403 }) as any);

    const result = await requireApiUser(createMockRequest({ authorization: 'Bearer test-token', method: 'POST' }));
    expect(result.userId).toBe(42);
    expect(result.authMethod).toBe('bearer');
  });
});

describe('authenticateApiRequest - empty bearer', () => {
  it('rejects empty Bearer token', async () => {
    await expect(
      authenticateApiRequest(createMockRequest({ authorization: 'Bearer ' }))
    ).rejects.toThrow(ApiAuthError);

    try {
      await authenticateApiRequest(createMockRequest({ authorization: 'Bearer ' }));
    } catch (e) {
      expect((e as ApiAuthError).status).toBe(401);
      expect((e as ApiAuthError).message).toBe('Invalid Bearer token');
    }
  });
});

describe('apiErrorResponse', () => {
  it('handles ApiAuthError', async () => {
    const response = apiErrorResponse(new ApiAuthError('Forbidden', 403));
    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toBe('Forbidden');
  });

  it('maps only an explicit NotFoundError to a safe 404', async () => {
    const response = apiErrorResponse(new NotFoundError('Token not found'));
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: 'Token not found' });
  });

  it.each([
    [new ApiValidationError('Safe validation detail'), 400],
    [new ApiConflictError('Safe conflict detail'), 409],
  ])('returns explicitly client-safe errors without an error ID', async (error, status) => {
    const response = apiErrorResponse(error);
    expect(response.status).toBe(status);
    expect(await response.json()).toEqual({ error: error.message });
  });

  it('answers 502 for a change that is stored but not live, and says it was saved', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const rejected = Object.assign(new CaddyApplyError('Caddy rejected configuration: the problem is in the WAF rules (proxy host a.example.com)', 'CADDY_REJECTED'), { proxyHostId: 12 });
    const response = apiErrorResponse(rejected);
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      error:
        'Saved, but not live yet: Caddy rejected configuration: the problem is in the WAF rules (proxy host a.example.com). ' +
        'Caddy keeps serving its previous configuration until an apply succeeds.',
      code: 'CADDY_REJECTED',
      saved: true,
      id: 12,
    });

    const unreachable = await apiErrorResponse(Object.assign(new CaddyApplyError('Unable to reach Caddy API', 'CADDY_UNREACHABLE'), { l4ProxyHostId: 4 })).json();
    expect(unreachable).toMatchObject({ code: 'CADDY_UNREACHABLE', saved: true, id: 4 });
    expect(unreachable.error).toMatch(/^Saved, but not live yet: Unable to reach Caddy API\./);

    const sync = apiErrorResponse(new CaddyApplyError('Caddy configuration applied but instance synchronization failed', 'INSTANCE_SYNC_FAILED'));
    expect(sync.status).toBe(502);
    expect(await sync.json()).toEqual({
      error: 'Saved and applied on this instance, but not on every instance: Caddy configuration applied but instance synchronization failed.',
      code: 'INSTANCE_SYNC_FAILED',
      saved: true,
    });
    consoleSpy.mockRestore();
  });

  it('prevents client-safe errors from being used to expose 5xx failures', () => {
    expect(() => new ApiClientError('must stay private', 500)).toThrow(
      /status must be a 4xx status code/
    );
  });

  it('handles generic Error', async () => {
    const sensitiveMessage = 'Caddy at http://caddy:2019 failed: secret detail';
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const failure = Object.assign(new Error(sensitiveMessage), {
      name: `Sensitive-${sensitiveMessage}`,
      code: `SECRET-${sensitiveMessage}`,
    });
    const response = apiErrorResponse(failure);
    expect(response.status).toBe(500);
    const data = await response.json();
    expect(data.error).toBe('Internal server error');
    expect(data.errorId).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.stringify(data)).not.toContain(sensitiveMessage);
    expect(JSON.stringify(consoleSpy.mock.calls)).not.toContain(sensitiveMessage);
    consoleSpy.mockRestore();
  });

  it('does not infer a safe 404 from an untyped internal error message', async () => {
    const response = apiErrorResponse(new Error('database table not found at /internal/path'));
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({ error: 'Internal server error' });
  });

  it('preserves legacy model 404 semantics without reflecting model details', async () => {
    const response = apiErrorResponse(new Error('Sensitive tenant record not found'));
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: 'Resource not found' });
  });

  it('handles unknown error', async () => {
    const response = apiErrorResponse('some string error');
    expect(response.status).toBe(500);
    const data = await response.json();
    expect(data.error).toBe('Internal server error');
    expect(data.errorId).toMatch(/^[0-9a-f-]{36}$/);
  });
});
